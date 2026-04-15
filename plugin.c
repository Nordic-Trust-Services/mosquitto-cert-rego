/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

/*
 * cert-rego: external X.509 client-certificate authentication with a Rego
 * policy as the authorisation decision engine. LDAP, OCSP, HTTP (OAuth2
 * introspection etc.), and any future external services are reachable
 * from inside Rego via host functions. The plugin itself makes no
 * authorisation decisions and has no hardcoded LDAP/OCSP/identity flow.
 *
 * Flow on MOSQ_EVT_BASIC_AUTH:
 *
 *   1. Retrieve the leaf via mosquitto_client_certificate(). No cert ->
 *      defer.
 *
 *   2. Build + verify the chain against the plugin trust store. The
 *      store may span multiple roots (comma-separated cert_rego_ca_file).
 *      Fail closed on verification error.
 *
 *   3. Build the Rego input doc from the leaf + trust anchor + full
 *      verified chain. No password anywhere. The CONNECT username is
 *      surfaced at input.connect.username so policies may read it.
 *
 *   4. Evaluate `data.mqtt.connect.allow`. The chain is made accessible
 *      to the ocsp.check() host function so Rego can invoke OCSP on
 *      whichever certs it cares about. The policy combines the OCSP
 *      result (if called), cert fields, LDAP lookups, and anything else
 *      into a bool.
 *
 *   5. Clean up the X509_STORE_CTX and return.
 *
 * Flow on MOSQ_EVT_ACL_CHECK: identical in shape, but evaluates
 * `data.mqtt.acl.allow` with an `acl` sub-object describing the
 * publish/subscribe request.
 *
 * Flow on MOSQ_EVT_RELOAD: reparse options, rebuild trust store, reparse
 * the Rego policy file, reopen the audit log. Swap atomically; any
 * failure leaves previous state in place.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#ifndef WIN32
#  include <strings.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <mosquitto.h>

#include "cert_auth.h"
#include "audit_log.h"
#include "crl_fetch.h"
#include "ldap_query.h"
#include "rego_engine.h"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *plg_id = NULL;
static struct ca_plugin plg_state;


/* ---- small helpers ---------------------------------------------------- */

static int64_t now_unix_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (int64_t)tv.tv_sec * 1000 + (int64_t)(tv.tv_usec / 1000);
}


static bool parse_bool(const char *s)
{
	return !strcasecmp(s, "true") || !strcasecmp(s, "yes") || !strcmp(s, "1");
}


/* Split a comma-separated list into a NULL-terminated string array. */
static char **split_csv(const char *s, size_t *count_out)
{
	*count_out = 0;
	if(!s || s[0] == '\0') return NULL;

	size_t cap = 1;
	for(const char *p = s; *p; p++){
		if(*p == ',') cap++;
	}
	char **out = mosquitto_calloc(cap + 1, sizeof(char *));
	if(!out) return NULL;

	size_t n = 0;
	const char *start = s;
	for(const char *p = s; ; p++){
		if(*p == ',' || *p == '\0'){
			const char *a = start;
			size_t len = (size_t)(p - start);
			while(len > 0 && (a[0] == ' ' || a[0] == '\t')){ a++; len--; }
			while(len > 0 && (a[len-1] == ' ' || a[len-1] == '\t')){ len--; }
			if(len > 0){
				char *e = mosquitto_calloc(1, len + 1);
				if(!e){
					for(size_t i = 0; i < n; i++) mosquitto_free(out[i]);
					mosquitto_free(out);
					return NULL;
				}
				memcpy(e, a, len);
				out[n++] = e;
			}
			if(*p == '\0') break;
			start = p + 1;
		}
	}
	out[n] = NULL;
	*count_out = n;
	return out;
}


static void free_csv(char **arr, size_t count)
{
	if(!arr) return;
	for(size_t i = 0; i < count; i++) mosquitto_free(arr[i]);
	mosquitto_free(arr);
}


/* ---- trust store ------------------------------------------------------ */

/* Load every configured ca_file into a single X509_STORE. All roots share
 * one store — during chain build, OpenSSL will match against whichever
 * anchor validates. The Rego input later exposes which anchor won. */
static X509_STORE *build_trust_store(const struct ca_config *cfg)
{
	if(cfg->ca_file_count == 0 && cfg->ca_path == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: at least one of plugin_opt_cert_rego_ca_file "
				"or plugin_opt_cert_rego_ca_path must be set");
		return NULL;
	}

	X509_STORE *store = X509_STORE_new();
	if(!store){
		mosquitto_log_printf(MOSQ_LOG_ERR, "cert-rego: X509_STORE_new failed");
		return NULL;
	}

	/* Load ca_path once (if set) — it's a directory of hashed CA files. */
	if(cfg->ca_path){
		if(X509_STORE_load_locations(store, NULL, cfg->ca_path) != 1){
			unsigned long e = ERR_peek_last_error();
			char ebuf[256];
			ERR_error_string_n(e, ebuf, sizeof(ebuf));
			mosquitto_log_printf(MOSQ_LOG_ERR,
					"cert-rego: failed to load ca_path %s: %s",
					cfg->ca_path, ebuf);
			X509_STORE_free(store);
			ERR_clear_error();
			return NULL;
		}
	}

	/* Load each ca_file in turn. Any bundle can contain multiple roots +
	 * intermediates; OpenSSL merges them all into the one store. */
	for(size_t i = 0; i < cfg->ca_file_count; i++){
		if(X509_STORE_load_locations(store, cfg->ca_files[i], NULL) != 1){
			unsigned long e = ERR_peek_last_error();
			char ebuf[256];
			ERR_error_string_n(e, ebuf, sizeof(ebuf));
			mosquitto_log_printf(MOSQ_LOG_ERR,
					"cert-rego: failed to load ca_file %s: %s",
					cfg->ca_files[i], ebuf);
			X509_STORE_free(store);
			ERR_clear_error();
			return NULL;
		}
		mosquitto_log_printf(MOSQ_LOG_INFO,
				"cert-rego: loaded CA bundle %s", cfg->ca_files[i]);
	}

	return store;
}


/* ---- config parsing --------------------------------------------------- */

static void config_free(struct ca_config *cfg)
{
	free_csv(cfg->ca_files, cfg->ca_file_count);
	mosquitto_free(cfg->ca_path);
	mosquitto_free(cfg->rego.policy_file);
	mosquitto_free(cfg->rego.connect_entrypoint);
	mosquitto_free(cfg->rego.acl_entrypoint);
	free_csv(cfg->ldap.allowed_urls, cfg->ldap.allowed_url_count);
	mosquitto_free(cfg->ldap.ca_file);
	mosquitto_free(cfg->audit.file_path);
	memset(cfg, 0, sizeof(*cfg));
}


static int config_defaults(struct ca_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->ocsp_timeout_ms = 3000;
	cfg->ocsp_min_refresh_seconds = 86400;
	cfg->ocsp_require_signing_eku = true;

	/* AIA fetching off by default; fetching arbitrary URLs from cert
	 * contents is a deliberate opt-in for operators who know their PKI
	 * publishes caIssuers URLs. */
	cfg->aia_fetch_enabled = false;
	cfg->aia_fetch_timeout_ms = 3000;
	cfg->aia_fetch_max_depth = 4;
	cfg->aia_fetch_max_size = 65536;    /* 64 KB */
	cfg->aia_fetch_cache_ttl = 86400;   /* day — certs rarely change */

	/* CRL fetching — same defaults shape as AIA. Default cap is higher
	 * (1 MB) because real CRLs can get large once the revoked list grows.
	 * Cache TTL is 1 hour by default so we pick up new CRLs reasonably
	 * soon after publication but still absorb most of the bursty MQTT
	 * traffic without re-querying. */
	cfg->crl_fetch_enabled = false;
	cfg->crl_fetch_timeout_ms = 5000;
	cfg->crl_fetch_max_size = 1024 * 1024;
	cfg->crl_fetch_cache_ttl = 3600;

	/* Entrypoints are plain rule names. Policies expose `connect` and
	 * `acl` as boolean rules at package mqtt — no wrapper objects, no
	 * boilerplate. */
	cfg->rego.connect_entrypoint = mosquitto_strdup("data.mqtt.connect");
	cfg->rego.acl_entrypoint = mosquitto_strdup("data.mqtt.acl");
	if(!cfg->rego.connect_entrypoint || !cfg->rego.acl_entrypoint){
		config_free(cfg);
		return -1;
	}

	cfg->ldap.require_tls = true;
	cfg->ldap.connect_timeout_ms = 3000;
	cfg->ldap.op_timeout_ms = 5000;
	cfg->ldap.search_cache_ttl = 60;

	cfg->audit.fsync_per_line = false;
	cfg->acl_include_payload = false;
	return 0;
}


static int config_set_str(char **dst, const char *v)
{
	mosquitto_free(*dst);
	*dst = mosquitto_strdup(v);
	return (*dst == NULL) ? -1 : 0;
}


static int config_parse_option(struct ca_config *cfg, const char *k, const char *v)
{
	if(!strcasecmp(k, "cert_rego_ca_file")){
		/* Comma-separated list of PEM bundles, all loaded into one store.
		 * Every call replaces the previous list (matters for reload). */
		free_csv(cfg->ca_files, cfg->ca_file_count);
		cfg->ca_files = split_csv(v, &cfg->ca_file_count);
		return 0;
	}else if(!strcasecmp(k, "cert_rego_ca_path")){
		return config_set_str(&cfg->ca_path, v);
	}else if(!strcasecmp(k, "cert_rego_policy_file")){
		return config_set_str(&cfg->rego.policy_file, v);
	}else if(!strcasecmp(k, "cert_rego_connect_entrypoint")){
		return config_set_str(&cfg->rego.connect_entrypoint, v);
	}else if(!strcasecmp(k, "cert_rego_acl_entrypoint")){
		return config_set_str(&cfg->rego.acl_entrypoint, v);
	}else if(!strcasecmp(k, "cert_rego_ldap_allowed_urls")){
		free_csv(cfg->ldap.allowed_urls, cfg->ldap.allowed_url_count);
		cfg->ldap.allowed_urls = split_csv(v, &cfg->ldap.allowed_url_count);
		return 0;
	}else if(!strcasecmp(k, "cert_rego_ldap_require_tls")){
		cfg->ldap.require_tls = parse_bool(v);
	}else if(!strcasecmp(k, "cert_rego_ldap_ca_file")){
		return config_set_str(&cfg->ldap.ca_file, v);
	}else if(!strcasecmp(k, "cert_rego_ldap_connect_timeout_ms")){
		cfg->ldap.connect_timeout_ms = strtol(v, NULL, 10);
	}else if(!strcasecmp(k, "cert_rego_ldap_op_timeout_ms")){
		cfg->ldap.op_timeout_ms = strtol(v, NULL, 10);
	}else if(!strcasecmp(k, "cert_rego_ldap_cache_ttl")){
		cfg->ldap.search_cache_ttl = (time_t)strtoll(v, NULL, 10);
	}else if(!strcasecmp(k, "cert_rego_audit_log_file")){
		return config_set_str(&cfg->audit.file_path, v);
	}else if(!strcasecmp(k, "cert_rego_audit_log_fsync")){
		cfg->audit.fsync_per_line = parse_bool(v);
	}else if(!strcasecmp(k, "cert_rego_acl_include_payload")){
		cfg->acl_include_payload = parse_bool(v);
	}else if(!strcasecmp(k, "cert_rego_ocsp_timeout_ms")){
		cfg->ocsp_timeout_ms = strtol(v, NULL, 10);
	}else if(!strcasecmp(k, "cert_rego_ocsp_min_refresh")){
		cfg->ocsp_min_refresh_seconds = (time_t)strtoll(v, NULL, 10);
	}else if(!strcasecmp(k, "cert_rego_ocsp_require_signing_eku")){
		cfg->ocsp_require_signing_eku = parse_bool(v);
	}else if(!strcasecmp(k, "cert_rego_aia_fetch_enabled")){
		cfg->aia_fetch_enabled = parse_bool(v);
	}else if(!strcasecmp(k, "cert_rego_aia_fetch_timeout_ms")){
		cfg->aia_fetch_timeout_ms = strtol(v, NULL, 10);
	}else if(!strcasecmp(k, "cert_rego_aia_fetch_max_depth")){
		cfg->aia_fetch_max_depth = (int)strtol(v, NULL, 10);
		if(cfg->aia_fetch_max_depth < 0) cfg->aia_fetch_max_depth = 0;
		if(cfg->aia_fetch_max_depth > 8) cfg->aia_fetch_max_depth = 8;
	}else if(!strcasecmp(k, "cert_rego_aia_fetch_max_size")){
		long long ms = strtoll(v, NULL, 10);
		if(ms < 1024) ms = 1024;
		if(ms > 1024 * 1024) ms = 1024 * 1024;
		cfg->aia_fetch_max_size = (size_t)ms;
	}else if(!strcasecmp(k, "cert_rego_aia_fetch_cache_ttl")){
		cfg->aia_fetch_cache_ttl = (time_t)strtoll(v, NULL, 10);
		if(cfg->aia_fetch_cache_ttl < 0) cfg->aia_fetch_cache_ttl = 0;
	}else if(!strcasecmp(k, "cert_rego_crl_fetch_enabled")){
		cfg->crl_fetch_enabled = parse_bool(v);
	}else if(!strcasecmp(k, "cert_rego_crl_fetch_timeout_ms")){
		cfg->crl_fetch_timeout_ms = strtol(v, NULL, 10);
	}else if(!strcasecmp(k, "cert_rego_crl_fetch_max_size")){
		long long ms = strtoll(v, NULL, 10);
		if(ms < 1024) ms = 1024;
		if(ms > 16 * 1024 * 1024) ms = 16 * 1024 * 1024;
		cfg->crl_fetch_max_size = (size_t)ms;
	}else if(!strcasecmp(k, "cert_rego_crl_fetch_cache_ttl")){
		cfg->crl_fetch_cache_ttl = (time_t)strtoll(v, NULL, 10);
		if(cfg->crl_fetch_cache_ttl < 0) cfg->crl_fetch_cache_ttl = 0;
	}else{
		mosquitto_log_printf(MOSQ_LOG_DEBUG,
				"cert-rego: ignoring unknown plugin_opt '%s'", k);
	}
	return 0;
}


static int config_load(struct ca_config *cfg,
		struct mosquitto_opt *options, int option_count)
{
	if(config_defaults(cfg) != 0) return -1;

	for(int i = 0; i < option_count; i++){
		if(config_parse_option(cfg, options[i].key, options[i].value) != 0){
			config_free(cfg);
			return -1;
		}
	}

	if(!cfg->rego.policy_file){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: plugin_opt_cert_rego_policy_file is required");
		config_free(cfg);
		return -1;
	}
	return 0;
}


/* ---- input document builders ------------------------------------------ */

static char *build_client_fragment(struct mosquitto *client)
{
	const char *id = mosquitto_client_id(client);
	const char *addr = mosquitto_client_address(client);

	char *id_esc = audit_log_escape_json_string(id ? id : "");
	char *addr_esc = audit_log_escape_json_string(addr ? addr : "");
	if(!id_esc || !addr_esc){
		mosquitto_free(id_esc);
		mosquitto_free(addr_esc);
		return NULL;
	}

	int proto_ver = mosquitto_client_protocol_version(client);

	size_t cap = 512;
	char *out = mosquitto_malloc(cap);
	if(!out){
		mosquitto_free(id_esc);
		mosquitto_free(addr_esc);
		return NULL;
	}
	int n = snprintf(out, cap,
			"\"id\":%s,\"address\":%s,\"protocol_version\":%d",
			id_esc, addr_esc, proto_ver);
	mosquitto_free(id_esc);
	mosquitto_free(addr_esc);
	if(n < 0 || (size_t)n >= cap){
		mosquitto_free(out);
		return NULL;
	}
	return out;
}


/* Passwordless connect input: cert + client + optional username only.
 * No password field exists at all. */
static char *build_connect_input(struct mosquitto *client,
		const char *username,
		const char *cert_json)
{
	char *client_frag = build_client_fragment(client);
	char *uname_esc = audit_log_escape_json_string(username ? username : "");

	if(!client_frag || !uname_esc){
		mosquitto_free(client_frag);
		mosquitto_free(uname_esc);
		return NULL;
	}

	size_t cert_len = cert_json ? strlen(cert_json) : 4;
	size_t cap = cert_len + strlen(client_frag) + strlen(uname_esc) + 256;
	char *out = mosquitto_malloc(cap);
	if(!out){
		mosquitto_free(client_frag);
		mosquitto_free(uname_esc);
		return NULL;
	}
	/* No `event` field: the entrypoint (data.mqtt.connect) already
	 * disambiguates — policies don't need to check what kind of
	 * decision they're being asked for. */
	int n = snprintf(out, cap,
			"{\"now_unix_ms\":%lld,"
			"\"client\":{%s},"
			"\"cert\":%s,"
			"\"connect\":{\"username\":%s}}",
			(long long)now_unix_ms(),
			client_frag,
			cert_json ? cert_json : "null",
			uname_esc);
	mosquitto_free(client_frag);
	mosquitto_free(uname_esc);
	if(n < 0 || (size_t)n >= cap){
		mosquitto_free(out);
		return NULL;
	}
	return out;
}


static const char *acl_action_string(int access)
{
	switch(access){
		case MOSQ_ACL_READ:        return "read";
		case MOSQ_ACL_WRITE:       return "write";
		case MOSQ_ACL_SUBSCRIBE:   return "subscribe";
		case MOSQ_ACL_UNSUBSCRIBE: return "unsubscribe";
		default:                   return "unknown";
	}
}


static char *base64_encode(const void *data, size_t len)
{
	int enc_max = 4 * (int)((len + 2) / 3) + 1;
	char *out = mosquitto_malloc((size_t)enc_max);
	if(!out) return NULL;
	int n = EVP_EncodeBlock((unsigned char *)out, (const unsigned char *)data, (int)len);
	if(n < 0){ mosquitto_free(out); return NULL; }
	out[n] = '\0';
	return out;
}


static char *build_acl_input(struct mosquitto *client,
		const char *cert_json,
		int access, const char *topic,
		const void *payload, uint32_t payloadlen,
		uint8_t qos, bool retain,
		bool include_payload)
{
	char *client_frag = build_client_fragment(client);
	char *topic_esc = audit_log_escape_json_string(topic ? topic : "");
	char *payload_b64 = NULL;
	char *payload_esc = NULL;

	if(include_payload && payload && payloadlen > 0){
		payload_b64 = base64_encode(payload, payloadlen);
		if(!payload_b64){ mosquitto_free(client_frag); mosquitto_free(topic_esc); return NULL; }
		payload_esc = audit_log_escape_json_string(payload_b64);
		mosquitto_free(payload_b64);
	}

	if(!client_frag || !topic_esc || (include_payload && !payload_esc)){
		mosquitto_free(client_frag);
		mosquitto_free(topic_esc);
		mosquitto_free(payload_esc);
		return NULL;
	}

	size_t cert_len = cert_json ? strlen(cert_json) : 4;
	size_t extra = (payload_esc ? strlen(payload_esc) : 4) + 256;
	size_t cap = cert_len + strlen(client_frag) + strlen(topic_esc) + extra;
	char *out = mosquitto_malloc(cap);
	if(!out){
		mosquitto_free(client_frag);
		mosquitto_free(topic_esc);
		mosquitto_free(payload_esc);
		return NULL;
	}

	int n;
	if(include_payload && payload_esc){
		n = snprintf(out, cap,
				"{\"now_unix_ms\":%lld,"
				"\"client\":{%s},"
				"\"cert\":%s,"
				"\"acl\":{\"action\":\"%s\",\"topic\":%s,\"qos\":%u,\"retain\":%s,\"payload_b64\":%s}}",
				(long long)now_unix_ms(),
				client_frag,
				cert_json ? cert_json : "null",
				acl_action_string(access),
				topic_esc,
				(unsigned)qos,
				retain ? "true" : "false",
				payload_esc);
	}else{
		n = snprintf(out, cap,
				"{\"now_unix_ms\":%lld,"
				"\"client\":{%s},"
				"\"cert\":%s,"
				"\"acl\":{\"action\":\"%s\",\"topic\":%s,\"qos\":%u,\"retain\":%s}}",
				(long long)now_unix_ms(),
				client_frag,
				cert_json ? cert_json : "null",
				acl_action_string(access),
				topic_esc,
				(unsigned)qos,
				retain ? "true" : "false");
	}

	mosquitto_free(client_frag);
	mosquitto_free(topic_esc);
	mosquitto_free(payload_esc);
	if(n < 0 || (size_t)n >= cap){
		mosquitto_free(out);
		return NULL;
	}
	return out;
}


/* ---- callbacks --------------------------------------------------------
 *
 * DEFAULT-DENY INVARIANT.
 *
 * Both callbacks below preserve this invariant:
 *
 *   - rc is initialised to MOSQ_ERR_AUTH (or MOSQ_ERR_ACL_DENIED).
 *   - The ONLY path that assigns rc = MOSQ_ERR_SUCCESS is reached after
 *     Rego evaluated the policy and returned allow == true.
 *   - Every other path — missing Rego engine, failed chain build (OOM),
 *     failed input-doc build, Rego eval error, Rego panic, undefined
 *     Rego result, explicit Rego deny — preserves the default-deny rc.
 *
 * A request that reaches our callback without rego producing true is
 * denied. This is why the plugin_init hard-fails on rego_engine_new
 * failure: a plugin loaded without a working engine would still default-
 * deny here, but operators should know that at startup, not discover it
 * through mysterious client rejections.
 *
 * The one non-deny exit is MOSQ_ERR_PLUGIN_DEFER when no client cert is
 * presented — this plugin only speaks to TLS-with-client-cert traffic;
 * cert-less connects fall through to other auth mechanisms the broker
 * may have configured. A listener that wants hard cert-only auth
 * achieves that via the listener's `require_certificate true` option
 * (which rejects the TLS handshake itself before we ever see the
 * client).
 * ---------------------------------------------------------------------- */

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	struct ca_plugin *plg = userdata;
	X509 *leaf = NULL;
	X509_STORE_CTX *ctx = NULL;
	STACK_OF(X509) *chain = NULL;
	X509 *anchor = NULL;
	struct ca_verify_state vstate;
	char *cert_json = NULL;
	char *input_real = NULL;
	bool allow = false;
	int rc = MOSQ_ERR_AUTH;

	UNUSED(event);

	leaf = (X509 *)mosquitto_client_certificate(ed->client);
	if(leaf == NULL){
		/* No cert on this listener — defer to other auth mechanisms. */
		return MOSQ_ERR_PLUGIN_DEFER;
	}

	if(!plg->rego){
		/* Should be unreachable: plugin_init refuses to load if
		 * rego_engine_new fails. Defence in depth if something unusual
		 * clears plg->rego later — default-deny plus loud audit. */
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: rego engine not initialised, denying");
		audit_log_event(plg->audit, "connect", "deny",
				"\"stage\":\"no_rego_engine\"");
		goto out;
	}

	/* Build + inspect the chain. ca_verify_chain collects per-cert
	 * errors but does NOT abort on failure — Rego is authoritative and
	 * may legitimately override specific failure modes (e.g. accept an
	 * expired intermediate during a root rotation). */
	rc = ca_verify_chain(plg, leaf, &ctx, &chain, &anchor, &vstate);
	if(rc != MOSQ_ERR_SUCCESS){
		/* Only OOM or other catastrophic failure reaches here. A failed
		 * verification returns SUCCESS with vstate.chain_ok == false. */
		audit_log_event(plg->audit, "connect", "deny", "\"stage\":\"verify_error\"");
		goto out;
	}
	(void)anchor;  /* anchor is emitted inside ca_cert_input_json */

	/* Build the input doc with all cert fields + chain + per-cert
	 * verification results. */
	cert_json = ca_cert_input_json(leaf, chain, &vstate);
	if(!cert_json){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: failed to build cert input json");
		audit_log_event(plg->audit, "connect", "deny",
				"\"stage\":\"input_build_error\"");
		rc = MOSQ_ERR_AUTH;
		goto out;
	}

	input_real = build_connect_input(ed->client, ed->username, cert_json);
	if(!input_real){
		audit_log_event(plg->audit, "connect", "deny",
				"\"stage\":\"input_build_error\"");
		rc = MOSQ_ERR_AUTH;
		goto out;
	}

	/* Step 5: Rego policy. Pass the chain so ocsp.check() can find it.
	 * Fail closed on error. */
	if(rego_engine_eval_bool_with_chain(plg->rego,
			plg->cfg.rego.connect_entrypoint,
			input_real, chain, &allow) != 0){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: policy evaluation failed, denying (fail-closed)");
		allow = false;
	}

	if(!allow){
		audit_log_event(plg->audit, "connect", "deny", "\"stage\":\"rego\"");
		rc = MOSQ_ERR_AUTH;
		goto out;
	}

	audit_log_event(plg->audit, "connect", "allow", NULL);
	rc = MOSQ_ERR_SUCCESS;

out:
	/* Step 7: clean up the chain context. */
	if(ctx){
		X509_STORE_CTX_cleanup(ctx);
		X509_STORE_CTX_free(ctx);
	}
	if(leaf) X509_free(leaf);
	mosquitto_free(cert_json);
	mosquitto_free(input_real);
	return rc;
}


static int acl_check_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_acl_check *ed = event_data;
	struct ca_plugin *plg = userdata;
	X509 *leaf = NULL;
	X509_STORE_CTX *ctx = NULL;
	STACK_OF(X509) *chain = NULL;
	X509 *anchor = NULL;
	struct ca_verify_state vstate;
	char *cert_json = NULL;
	char *input_real = NULL;
	bool allow = false;
	int rc = MOSQ_ERR_ACL_DENIED;

	UNUSED(event);

	if(!plg->rego){
		/* Same defence-in-depth posture as basic_auth. Should be
		 * unreachable; still default-deny with an audit event. */
		audit_log_event(plg->audit, "acl", "deny",
				"\"stage\":\"no_rego_engine\"");
		return MOSQ_ERR_ACL_DENIED;
	}

	leaf = (X509 *)mosquitto_client_certificate(ed->client);
	if(leaf == NULL){
		return MOSQ_ERR_PLUGIN_DEFER;
	}

	/* Re-verify the chain for each ACL check, collecting the same per-cert
	 * verification state as CONNECT. Rego ACL policies see the chain plus
	 * chain_ok / chain_errors so they can apply the same override logic
	 * as the connect rule. */
	if(ca_verify_chain(plg, leaf, &ctx, &chain, &anchor, &vstate) != MOSQ_ERR_SUCCESS){
		rc = MOSQ_ERR_ACL_DENIED;
		goto out;
	}
	(void)anchor;

	cert_json = ca_cert_input_json(leaf, chain, &vstate);
	if(!cert_json){
		goto out;
	}

	input_real = build_acl_input(ed->client, cert_json,
			ed->access, ed->topic,
			ed->payload, ed->payloadlen,
			(uint8_t)ed->qos, ed->retain,
			plg->cfg.acl_include_payload);
	if(!input_real){
		goto out;
	}

	if(rego_engine_eval_bool_with_chain(plg->rego, plg->cfg.rego.acl_entrypoint,
			input_real, chain, &allow) != 0){
		allow = false;
	}

	{
		char extras[512];
		char *topic_esc = audit_log_escape_json_string(ed->topic ? ed->topic : "");
		if(topic_esc){
			snprintf(extras, sizeof(extras),
					"\"action\":\"%s\",\"topic\":%s,\"qos\":%u",
					acl_action_string(ed->access), topic_esc, (unsigned)ed->qos);
			audit_log_event(plg->audit, "acl", allow ? "allow" : "deny", extras);
			mosquitto_free(topic_esc);
		}
	}

	rc = allow ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED;

out:
	if(ctx){
		X509_STORE_CTX_cleanup(ctx);
		X509_STORE_CTX_free(ctx);
	}
	if(leaf) X509_free(leaf);
	mosquitto_free(cert_json);
	mosquitto_free(input_real);
	return rc;
}


static int reload_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_reload *ed = event_data;
	struct ca_plugin *plg = userdata;
	struct ca_config new_cfg;
	X509_STORE *new_trust = NULL;
	struct audit_log *new_audit = NULL;

	UNUSED(event);

	mosquitto_log_printf(MOSQ_LOG_INFO, "cert-rego: reload requested");

	if(config_load(&new_cfg, ed->options, ed->option_count) != 0){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: reload: config load failed, keeping previous");
		return MOSQ_ERR_SUCCESS;
	}

	new_trust = build_trust_store(&new_cfg);
	if(!new_trust){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: reload: trust store build failed, keeping previous");
		config_free(&new_cfg);
		return MOSQ_ERR_SUCCESS;
	}

	if(rego_engine_reload(plg->rego, new_cfg.rego.policy_file) != 0){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: reload: policy reload failed, keeping previous");
		X509_STORE_free(new_trust);
		config_free(&new_cfg);
		return MOSQ_ERR_SUCCESS;
	}

	new_audit = audit_log_open(new_cfg.audit.file_path, new_cfg.audit.fsync_per_line);

	/* AIA / CRL caches: create if the new config enables the feature and
	 * we don't already have one; drop if disabled. Keep across reloads
	 * that leave the flag on (operators rarely want a full cache flush
	 * on SIGHUP). */
	struct aia_cache *new_aia = plg->aia_cache;
	if(new_cfg.aia_fetch_enabled && !new_aia){
		new_aia = aia_cache_new();
	}else if(!new_cfg.aia_fetch_enabled && new_aia){
		aia_cache_free(new_aia);
		new_aia = NULL;
	}
	struct crl_cache *new_crl = plg->crl_cache;
	if(new_cfg.crl_fetch_enabled && !new_crl){
		new_crl = crl_cache_new();
	}else if(!new_cfg.crl_fetch_enabled && new_crl){
		crl_cache_free(new_crl);
		new_crl = NULL;
	}

	audit_log_close(plg->audit);
	X509_STORE_free(plg->trust_store);
	config_free(&plg->cfg);

	plg->cfg = new_cfg;
	plg->trust_store = new_trust;
	plg->audit = new_audit;
	plg->aia_cache = new_aia;
	plg->crl_cache = new_crl;

	audit_log_event(plg->audit, "plugin.reload", "ok", NULL);
	return MOSQ_ERR_SUCCESS;
}


/* ---- init / cleanup --------------------------------------------------- */

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data,
		struct mosquitto_opt *options, int option_count)
{
	UNUSED(user_data);

	memset(&plg_state, 0, sizeof(plg_state));

	if(config_load(&plg_state.cfg, options, option_count) != 0){
		return MOSQ_ERR_INVAL;
	}

	plg_state.trust_store = build_trust_store(&plg_state.cfg);
	if(!plg_state.trust_store){
		config_free(&plg_state.cfg);
		return MOSQ_ERR_INVAL;
	}

	plg_state.cache = ca_cache_new();
	if(!plg_state.cache){
		X509_STORE_free(plg_state.trust_store);
		plg_state.trust_store = NULL;
		config_free(&plg_state.cfg);
		return MOSQ_ERR_NOMEM;
	}

	if(plg_state.cfg.aia_fetch_enabled){
		plg_state.aia_cache = aia_cache_new();
		if(!plg_state.aia_cache){
			ca_cache_free(plg_state.cache);
			plg_state.cache = NULL;
			X509_STORE_free(plg_state.trust_store);
			plg_state.trust_store = NULL;
			config_free(&plg_state.cfg);
			return MOSQ_ERR_NOMEM;
		}
	}

	if(plg_state.cfg.crl_fetch_enabled){
		plg_state.crl_cache = crl_cache_new();
		if(!plg_state.crl_cache){
			if(plg_state.aia_cache){
				aia_cache_free(plg_state.aia_cache);
				plg_state.aia_cache = NULL;
			}
			ca_cache_free(plg_state.cache);
			plg_state.cache = NULL;
			X509_STORE_free(plg_state.trust_store);
			plg_state.trust_store = NULL;
			config_free(&plg_state.cfg);
			return MOSQ_ERR_NOMEM;
		}
	}

	plg_state.audit = audit_log_open(plg_state.cfg.audit.file_path,
			plg_state.cfg.audit.fsync_per_line);

	plg_state.rego = rego_engine_new(&plg_state, plg_state.cfg.rego.policy_file);
	if(!plg_state.rego){
		audit_log_close(plg_state.audit);
		plg_state.audit = NULL;
		if(plg_state.crl_cache){
			crl_cache_free(plg_state.crl_cache);
			plg_state.crl_cache = NULL;
		}
		if(plg_state.aia_cache){
			aia_cache_free(plg_state.aia_cache);
			plg_state.aia_cache = NULL;
		}
		ca_cache_free(plg_state.cache);
		plg_state.cache = NULL;
		X509_STORE_free(plg_state.trust_store);
		plg_state.trust_store = NULL;
		config_free(&plg_state.cfg);
		return MOSQ_ERR_INVAL;
	}

	plg_id = identifier;
	mosquitto_plugin_set_info(identifier, "cert-rego", NULL);

	int rc;
	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH,
			basic_auth_callback, NULL, &plg_state);
	if(rc != MOSQ_ERR_SUCCESS) goto init_fail;

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK,
			acl_check_callback, NULL, &plg_state);
	if(rc != MOSQ_ERR_SUCCESS) goto init_fail;

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_RELOAD,
			reload_callback, NULL, &plg_state);
	if(rc != MOSQ_ERR_SUCCESS) goto init_fail;

	mosquitto_log_printf(MOSQ_LOG_INFO,
			"cert-rego: loaded (policy=%s, roots=%zu, ldap_urls=%zu, audit=%s)",
			plg_state.cfg.rego.policy_file,
			plg_state.cfg.ca_file_count + (plg_state.cfg.ca_path ? 1 : 0),
			plg_state.cfg.ldap.allowed_url_count,
			plg_state.cfg.audit.file_path ? plg_state.cfg.audit.file_path : "(none)");
	audit_log_event(plg_state.audit, "plugin.init", "ok", NULL);
	return MOSQ_ERR_SUCCESS;

init_fail:
	mosquitto_log_printf(MOSQ_LOG_ERR,
			"cert-rego: callback registration failed (rc=%d)", rc);
	rego_engine_drop(plg_state.rego);
	plg_state.rego = NULL;
	audit_log_close(plg_state.audit);
	plg_state.audit = NULL;
	if(plg_state.crl_cache){
		crl_cache_free(plg_state.crl_cache);
		plg_state.crl_cache = NULL;
	}
	if(plg_state.aia_cache){
		aia_cache_free(plg_state.aia_cache);
		plg_state.aia_cache = NULL;
	}
	ca_cache_free(plg_state.cache);
	plg_state.cache = NULL;
	X509_STORE_free(plg_state.trust_store);
	plg_state.trust_store = NULL;
	config_free(&plg_state.cfg);
	return rc;
}


int mosquitto_plugin_cleanup(void *user_data,
		struct mosquitto_opt *options, int option_count)
{
	UNUSED(user_data);
	UNUSED(options);
	UNUSED(option_count);

	audit_log_event(plg_state.audit, "plugin.shutdown", "ok", NULL);

	if(plg_state.rego){
		rego_engine_drop(plg_state.rego);
		plg_state.rego = NULL;
	}
	if(plg_state.audit){
		audit_log_close(plg_state.audit);
		plg_state.audit = NULL;
	}
	if(plg_state.crl_cache){
		crl_cache_free(plg_state.crl_cache);
		plg_state.crl_cache = NULL;
	}
	if(plg_state.aia_cache){
		aia_cache_free(plg_state.aia_cache);
		plg_state.aia_cache = NULL;
	}
	if(plg_state.cache){
		ca_cache_free(plg_state.cache);
		plg_state.cache = NULL;
	}
	if(plg_state.trust_store){
		X509_STORE_free(plg_state.trust_store);
		plg_state.trust_store = NULL;
	}
	config_free(&plg_state.cfg);
	return MOSQ_ERR_SUCCESS;
}
