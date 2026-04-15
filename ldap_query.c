/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

/*
 * libldap wrapper for the Rego ldap.* custom builtins.
 *
 * Design notes:
 *
 *   - One LDAP connection per call. No pooling. mosquitto is single-threaded
 *     and LDAP connections aren't free to keep open with credential rotation
 *     — simpler and safer than a pool that has to handle stale bind state.
 *     Rebind once per operation, unbind at the end.
 *
 *   - Every network call respects cfg->connect_timeout_ms and op_timeout_ms.
 *     Both are set via LDAP_OPT_NETWORK_TIMEOUT and LDAP_OPT_TIMEOUT so the
 *     library enforces them at the libldap level.
 *
 *   - ldaps:// vs ldap:// is enforced by the URL whitelist + require_tls
 *     flag at the top of every entry point. Policies cannot step around
 *     this because the whitelist lives in plugin config, not policy.
 *
 *   - Every call emits an audit log line with the url, base, filter (or
 *     equivalent), and outcome. Passwords never appear in the audit stream.
 *
 *   - JSON result serialisation is hand-written (no cJSON dep) because the
 *     format is narrow and stable. Values from LDAP are binary — we emit
 *     them as UTF-8 strings when printable, otherwise base64, following the
 *     LDIF convention.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <ldap.h>

#include <mosquitto.h>

#include "cert_auth.h"
#include "audit_log.h"
#include "ldap_query.h"


/* ---- small helpers ----------------------------------------------------- */

const char *ldap_query_rc_str(enum ldap_query_rc rc)
{
	switch(rc){
		case LDAP_Q_OK:              return "ok";
		case LDAP_Q_DENIED:          return "denied";
		case LDAP_Q_URL_NOT_ALLOWED: return "url_not_allowed";
		case LDAP_Q_TLS_REQUIRED:    return "tls_required";
		case LDAP_Q_CONNECT_FAILED:  return "connect_failed";
		case LDAP_Q_TIMEOUT:         return "timeout";
		case LDAP_Q_BIND_FAILED:     return "bind_failed";
		case LDAP_Q_SEARCH_FAILED:   return "search_failed";
		case LDAP_Q_OOM:             return "oom";
		case LDAP_Q_INVAL:           return "invalid_arg";
	}
	return "unknown";
}


static bool starts_with_ci(const char *s, const char *prefix)
{
	size_t n = strlen(prefix);
	return strncasecmp(s, prefix, n) == 0;
}


/* Check the URL against cfg->allowed_urls. Exact match, case-insensitive. */
static bool url_is_whitelisted(const struct ca_ldap_config *cfg, const char *url)
{
	if(!cfg || !url) return false;
	for(size_t i = 0; i < cfg->allowed_url_count; i++){
		if(cfg->allowed_urls[i] && strcasecmp(cfg->allowed_urls[i], url) == 0){
			return true;
		}
	}
	return false;
}


static enum ldap_query_rc precheck_url(const struct ca_ldap_config *cfg, const char *url)
{
	if(!cfg) return LDAP_Q_INVAL;
	if(!url || url[0] == '\0') return LDAP_Q_INVAL;
	if(cfg->require_tls && !starts_with_ci(url, "ldaps://")){
		return LDAP_Q_TLS_REQUIRED;
	}
	if(!url_is_whitelisted(cfg, url)){
		return LDAP_Q_URL_NOT_ALLOWED;
	}
	return LDAP_Q_OK;
}


/* Parse scope string to libldap enum. Returns -1 on invalid. */
static int parse_scope(const char *scope)
{
	if(!scope || !*scope) return LDAP_SCOPE_SUBTREE;
	if(!strcasecmp(scope, "base")) return LDAP_SCOPE_BASE;
	if(!strcasecmp(scope, "one"))  return LDAP_SCOPE_ONELEVEL;
	if(!strcasecmp(scope, "sub"))  return LDAP_SCOPE_SUBTREE;
	return -1;
}


/* Split a comma-separated attrs list into a NULL-terminated array suitable
 * for ldap_search_ext_s. Returns NULL for "all attrs" (which libldap maps
 * to a NULL pointer). Caller frees the returned array and each string. */
static char **split_attrs(const char *attrs)
{
	if(!attrs || attrs[0] == '\0') return NULL;

	size_t count = 1;
	for(const char *p = attrs; *p; p++){
		if(*p == ',') count++;
	}

	char **out = mosquitto_calloc(count + 1, sizeof(char *));
	if(!out) return NULL;

	size_t i = 0;
	const char *start = attrs;
	for(const char *p = attrs; ; p++){
		if(*p == ',' || *p == '\0'){
			size_t len = (size_t)(p - start);
			while(len > 0 && (start[0] == ' ' || start[0] == '\t')){ start++; len--; }
			while(len > 0 && (start[len-1] == ' ' || start[len-1] == '\t')){ len--; }
			if(len > 0){
				char *s = mosquitto_calloc(1, len + 1);
				if(!s){ goto oom; }
				memcpy(s, start, len);
				out[i++] = s;
			}
			if(*p == '\0') break;
			start = p + 1;
		}
	}
	out[i] = NULL;
	return out;

oom:
	for(size_t j = 0; j < i; j++) mosquitto_free(out[j]);
	mosquitto_free(out);
	return NULL;
}


static void free_attrs(char **attrs)
{
	if(!attrs) return;
	for(size_t i = 0; attrs[i]; i++) mosquitto_free(attrs[i]);
	mosquitto_free(attrs);
}


/* ---- connection setup -------------------------------------------------- */

/* Open a connection, set options, optionally simple-bind. On success returns
 * LDAP_Q_OK and *ldp is an open, bound LDAP* the caller must ldap_unbind_ext_s.
 *
 * Pass bind_dn = NULL and bind_pw = NULL for an anonymous bind — which is
 * only useful for ldap.search with anon-readable directories.
 */
static enum ldap_query_rc open_and_bind(
		const struct ca_ldap_config *cfg,
		const char *url,
		const char *bind_dn,
		const char *bind_pw,
		LDAP **ldp)
{
	LDAP *ld = NULL;
	int version = LDAP_VERSION3;
	int rc;
	struct timeval net_tv, op_tv;

	*ldp = NULL;

	if(ldap_initialize(&ld, url) != LDAP_SUCCESS || !ld){
		return LDAP_Q_CONNECT_FAILED;
	}

	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	/* Refuse referrals — they can redirect to URLs outside the whitelist. */
	int referrals = 0;
	ldap_set_option(ld, LDAP_OPT_REFERRALS, &referrals);

	net_tv.tv_sec = cfg->connect_timeout_ms / 1000;
	net_tv.tv_usec = (cfg->connect_timeout_ms % 1000) * 1000;
	ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &net_tv);

	op_tv.tv_sec = cfg->op_timeout_ms / 1000;
	op_tv.tv_usec = (cfg->op_timeout_ms % 1000) * 1000;
	ldap_set_option(ld, LDAP_OPT_TIMEOUT, &op_tv);

	/* TLS: libldap reads these from its global context unless we force a
	 * new context for this handle. We do force a new one so the per-plugin
	 * CA file doesn't leak into unrelated LDAP consumers in the same process. */
	if(starts_with_ci(url, "ldaps://")){
		int require = LDAP_OPT_X_TLS_DEMAND;
		ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &require);

		if(cfg->ca_file){
			ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, cfg->ca_file);
		}

		int newctx = 0;
		ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &newctx);
	}

	/* Simple bind. A NULL bind_dn with a NULL cred does an anonymous bind. */
	struct berval cred;
	struct berval *cred_ptr = NULL;
	if(bind_pw){
		cred.bv_val = (char *)bind_pw;
		cred.bv_len = strlen(bind_pw);
		cred_ptr = &cred;
	}

	rc = ldap_sasl_bind_s(ld, bind_dn, LDAP_SASL_SIMPLE, cred_ptr,
			NULL, NULL, NULL);
	if(rc != LDAP_SUCCESS){
		ldap_unbind_ext_s(ld, NULL, NULL);
		return LDAP_Q_BIND_FAILED;
	}

	*ldp = ld;
	return LDAP_Q_OK;
}


/* ---- audit helpers ----------------------------------------------------- */

static void audit_ldap_event(
		struct audit_log *audit,
		const char *fn,
		const char *url,
		const char *extras_no_password,
		enum ldap_query_rc rc)
{
	if(!audit) return;
	char buf[1024];
	char *url_esc = audit_log_escape_json_string(url ? url : "");
	if(!url_esc) return;

	const char *result =
		(rc == LDAP_Q_OK) ? "ok" :
		(rc == LDAP_Q_DENIED) ? "deny" :
		"error";

	snprintf(buf, sizeof(buf),
			"\"fn\":\"%s\",\"url\":%s,\"rc\":\"%s\"%s%s",
			fn,
			url_esc,
			ldap_query_rc_str(rc),
			extras_no_password ? "," : "",
			extras_no_password ? extras_no_password : "");
	audit_log_event(audit, "ldap", result, buf);

	mosquitto_free(url_esc);
}


/* NOTE: no ldap_query_login.
 *
 * The plugin is passwordless. All bind operations in this module use the
 * service-account credentials passed by policies into ldap.search /
 * ldap.exists / ldap.is_member. A "verify a user's password" primitive
 * would inherently reintroduce a user-supplied credential into the
 * plugin, which is exactly what the design rejects. Use an OAuth2 /
 * OIDC identity provider (via rego-cpp's http.send) or mTLS identity
 * plus directory group membership (via ldap.is_member) instead. */


/* ---- ldap.search: result serialisation --------------------------------- */

/* Append a JSON-escaped string (with quotes) to a dynamic buffer. Returns
 * the new buffer (possibly reallocated) or NULL on OOM. */
struct dyn_buf {
	char *data;
	size_t len;
	size_t cap;
};

static bool buf_reserve(struct dyn_buf *b, size_t extra)
{
	if(b->len + extra + 1 <= b->cap) return true;
	size_t ncap = b->cap ? b->cap * 2 : 256;
	while(ncap < b->len + extra + 1) ncap *= 2;
	char *nd = mosquitto_realloc(b->data, ncap);
	if(!nd) return false;
	b->data = nd;
	b->cap = ncap;
	return true;
}

static bool buf_append_raw(struct dyn_buf *b, const char *s, size_t n)
{
	if(!buf_reserve(b, n)) return false;
	memcpy(b->data + b->len, s, n);
	b->len += n;
	b->data[b->len] = '\0';
	return true;
}

static bool buf_append_cstr(struct dyn_buf *b, const char *s)
{
	return buf_append_raw(b, s, strlen(s));
}

static bool buf_append_json_string(struct dyn_buf *b, const char *s)
{
	char *esc = audit_log_escape_json_string(s ? s : "");
	if(!esc) return false;
	bool ok = buf_append_cstr(b, esc);
	mosquitto_free(esc);
	return ok;
}

/* Escape a berval. If the content is valid UTF-8 with no embedded NULs we
 * emit it as a JSON string. Otherwise base64-encode and emit as
 * {"$b64":"..."} so the policy can tell the two cases apart. */
static bool buf_append_json_berval(struct dyn_buf *b, const struct berval *v)
{
	if(!v || !v->bv_val){
		return buf_append_cstr(b, "null");
	}

	bool is_text = true;
	for(unsigned long i = 0; i < v->bv_len; i++){
		unsigned char c = (unsigned char)v->bv_val[i];
		if(c == 0 || (c < 0x20 && c != '\t')){
			is_text = false;
			break;
		}
	}

	if(is_text){
		char *tmp = mosquitto_malloc(v->bv_len + 1);
		if(!tmp) return false;
		memcpy(tmp, v->bv_val, v->bv_len);
		tmp[v->bv_len] = '\0';
		bool ok = buf_append_json_string(b, tmp);
		mosquitto_free(tmp);
		return ok;
	}

	/* Base64 encode via OpenSSL EVP so we don't carry our own implementation.
	 * Output size is 4 * ceil(len/3). */
	int encoded_max = 4 * (int)((v->bv_len + 2) / 3) + 1;
	char *enc = mosquitto_malloc((size_t)encoded_max);
	if(!enc) return false;
	int encoded_len = EVP_EncodeBlock((unsigned char *)enc,
			(const unsigned char *)v->bv_val,
			(int)v->bv_len);
	if(encoded_len < 0){
		mosquitto_free(enc);
		return false;
	}
	enc[encoded_len] = '\0';

	bool ok = buf_append_cstr(b, "{\"$b64\":")
		&& buf_append_json_string(b, enc)
		&& buf_append_cstr(b, "}");
	mosquitto_free(enc);
	return ok;
}


/* Serialise the full result set into a JSON array of objects. Returns a
 * mosquitto_strdup'd string on success, NULL on OOM. */
static char *serialise_search_result(LDAP *ld, LDAPMessage *result)
{
	struct dyn_buf b = {0};
	if(!buf_append_cstr(&b, "[")) goto oom;

	bool first_entry = true;
	for(LDAPMessage *entry = ldap_first_entry(ld, result);
			entry != NULL;
			entry = ldap_next_entry(ld, entry)){

		if(!first_entry){
			if(!buf_append_cstr(&b, ",")) goto oom;
		}
		first_entry = false;

		if(!buf_append_cstr(&b, "{\"dn\":")) goto oom;
		char *dn = ldap_get_dn(ld, entry);
		if(!buf_append_json_string(&b, dn ? dn : "")) { if(dn) ldap_memfree(dn); goto oom; }
		if(dn) ldap_memfree(dn);

		if(!buf_append_cstr(&b, ",\"attrs\":{")) goto oom;

		BerElement *ber = NULL;
		bool first_attr = true;
		for(char *attr = ldap_first_attribute(ld, entry, &ber);
				attr != NULL;
				attr = ldap_next_attribute(ld, entry, ber)){

			if(!first_attr){
				if(!buf_append_cstr(&b, ",")){ ldap_memfree(attr); if(ber) ber_free(ber, 0); goto oom; }
			}
			first_attr = false;

			if(!buf_append_json_string(&b, attr)){ ldap_memfree(attr); if(ber) ber_free(ber, 0); goto oom; }
			if(!buf_append_cstr(&b, ":[")){ ldap_memfree(attr); if(ber) ber_free(ber, 0); goto oom; }

			struct berval **vals = ldap_get_values_len(ld, entry, attr);
			if(vals){
				for(int i = 0; vals[i] != NULL; i++){
					if(i > 0){
						if(!buf_append_cstr(&b, ",")){
							ldap_value_free_len(vals);
							ldap_memfree(attr);
							if(ber) ber_free(ber, 0);
							goto oom;
						}
					}
					if(!buf_append_json_berval(&b, vals[i])){
						ldap_value_free_len(vals);
						ldap_memfree(attr);
						if(ber) ber_free(ber, 0);
						goto oom;
					}
				}
				ldap_value_free_len(vals);
			}

			if(!buf_append_cstr(&b, "]")){ ldap_memfree(attr); if(ber) ber_free(ber, 0); goto oom; }
			ldap_memfree(attr);
		}
		if(ber) ber_free(ber, 0);

		if(!buf_append_cstr(&b, "}}")) goto oom;
	}

	if(!buf_append_cstr(&b, "]")) goto oom;
	return b.data;

oom:
	mosquitto_free(b.data);
	return NULL;
}


/* ---- ldap.search ------------------------------------------------------- */

/* Compute the cache key for a search call: SHA-256 over the concatenated
 * inputs with length-prefixed separators. bind_pw is hashed too, so caches
 * for the same search with different bind creds don't collide.
 */
static void search_cache_key(
		const char *url, const char *bind_dn, const char *bind_pw,
		const char *base_dn, int scope, const char *filter, const char *attrs,
		unsigned char out[32])
{
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md, EVP_sha256(), NULL);

#define FEED(s) do { \
		const char *_s = (s) ? (s) : ""; \
		uint32_t _l = (uint32_t)strlen(_s); \
		EVP_DigestUpdate(md, &_l, sizeof(_l)); \
		EVP_DigestUpdate(md, _s, _l); \
	} while(0)

	FEED(url);
	FEED(bind_dn);
	FEED(bind_pw);
	FEED(base_dn);
	{
		uint32_t sc = (uint32_t)scope;
		EVP_DigestUpdate(md, &sc, sizeof(sc));
	}
	FEED(filter);
	FEED(attrs);
#undef FEED

	unsigned int mdlen = 32;
	EVP_DigestFinal_ex(md, out, &mdlen);
	EVP_MD_CTX_free(md);
}


enum ldap_query_rc ldap_query_search(
		struct ldap_ctx *ctx,
		const char *url,
		const char *bind_dn,
		const char *bind_pw,
		const char *base_dn,
		const char *scope,
		const char *filter,
		const char *attrs,
		char **result_json_out)
{
	enum ldap_query_rc rc;
	LDAP *ld = NULL;
	LDAPMessage *result = NULL;
	char **attrs_arr = NULL;
	unsigned char key[32];
	int scope_enum;
	char extras[512];

	if(!ctx || !ctx->cfg || !base_dn || !filter || !result_json_out){
		return LDAP_Q_INVAL;
	}
	*result_json_out = NULL;

	rc = precheck_url(ctx->cfg, url);
	if(rc != LDAP_Q_OK){
		audit_ldap_event(ctx->audit, "search", url, NULL, rc);
		return rc;
	}

	scope_enum = parse_scope(scope);
	if(scope_enum < 0){
		audit_ldap_event(ctx->audit, "search", url, NULL, LDAP_Q_INVAL);
		return LDAP_Q_INVAL;
	}

	/* Cache lookup if enabled. */
	if(ctx->cache && ctx->cfg->search_cache_ttl > 0){
		search_cache_key(url, bind_dn, bind_pw, base_dn, scope_enum, filter, attrs, key);
		char *cached = ca_cache_blob_lookup(ctx->cache, CA_CACHE_LDAP_SEARCH, key, sizeof(key));
		if(cached){
			*result_json_out = cached;
			audit_ldap_event(ctx->audit, "search", url, "\"cache\":\"hit\"", LDAP_Q_OK);
			return LDAP_Q_OK;
		}
	}

	rc = open_and_bind(ctx->cfg, url, bind_dn, bind_pw, &ld);
	if(rc != LDAP_Q_OK){
		audit_ldap_event(ctx->audit, "search", url, NULL, rc);
		return rc;
	}

	attrs_arr = split_attrs(attrs);
	if(attrs && attrs[0] != '\0' && !attrs_arr){
		rc = LDAP_Q_OOM;
		goto out;
	}

	struct timeval op_tv;
	op_tv.tv_sec = ctx->cfg->op_timeout_ms / 1000;
	op_tv.tv_usec = (ctx->cfg->op_timeout_ms % 1000) * 1000;

	int srv = ldap_search_ext_s(ld, base_dn, scope_enum, filter,
			attrs_arr, 0, NULL, NULL, &op_tv, 0, &result);
	if(srv != LDAP_SUCCESS){
		rc = LDAP_Q_SEARCH_FAILED;
		snprintf(extras, sizeof(extras), "\"ldap_err\":%d", srv);
		audit_ldap_event(ctx->audit, "search", url, extras, rc);
		goto out;
	}

	*result_json_out = serialise_search_result(ld, result);
	if(!*result_json_out){
		rc = LDAP_Q_OOM;
		goto out;
	}

	/* Cache store if enabled. */
	if(ctx->cache && ctx->cfg->search_cache_ttl > 0){
		ca_cache_blob_store(ctx->cache, CA_CACHE_LDAP_SEARCH,
				key, sizeof(key),
				*result_json_out,
				time(NULL) + ctx->cfg->search_cache_ttl);
	}

	rc = LDAP_Q_OK;

	{
		int entries = ldap_count_entries(ld, result);
		snprintf(extras, sizeof(extras), "\"entries\":%d", entries);
		audit_ldap_event(ctx->audit, "search", url, extras, LDAP_Q_OK);
	}

out:
	if(result) ldap_msgfree(result);
	if(attrs_arr) free_attrs(attrs_arr);
	if(ld) ldap_unbind_ext_s(ld, NULL, NULL);
	return rc;
}


/* ---- ldap.exists ------------------------------------------------------- */

enum ldap_query_rc ldap_query_exists(
		struct ldap_ctx *ctx,
		const char *url,
		const char *bind_dn,
		const char *bind_pw,
		const char *base_dn,
		const char *filter,
		bool *result_out)
{
	char *json_res = NULL;
	enum ldap_query_rc rc;

	if(!result_out) return LDAP_Q_INVAL;
	*result_out = false;

	/* Ask for only the DN attribute (1.1 per RFC 4511) to make the query
	 * as cheap as possible — we only care about existence. */
	rc = ldap_query_search(ctx, url, bind_dn, bind_pw,
			base_dn, "sub", filter, "1.1", &json_res);
	if(rc != LDAP_Q_OK){
		return rc;
	}

	/* The result is a JSON array. If it starts with "[]" (possibly after
	 * whitespace) then no entries were found. We don't need a real parser
	 * for this — the serialiser's output is deterministic. */
	if(json_res){
		const char *p = json_res;
		while(*p == ' ' || *p == '\t' || *p == '\n') p++;
		if(*p == '[' && *(p+1) == ']'){
			*result_out = false;
		}else{
			*result_out = true;
		}
		mosquitto_free(json_res);
	}
	return LDAP_Q_OK;
}


/* ---- ldap.is_member ---------------------------------------------------- */

enum ldap_query_rc ldap_query_is_member(
		struct ldap_ctx *ctx,
		const char *url,
		const char *bind_dn,
		const char *bind_pw,
		const char *group_dn,
		const char *user_dn,
		bool *result_out)
{
	if(!group_dn || !user_dn || !result_out){
		return LDAP_Q_INVAL;
	}
	*result_out = false;

	/* Build a compound filter: (&(objectClass=*)(member=<user_dn>)) scoped
	 * at the group DN with base scope. Succeeds iff the group entry exists
	 * AND has the given user as a member.
	 *
	 * user_dn has to go into an LDAP filter, which means escaping the
	 * RFC 4515 metacharacters: * ( ) \ NUL. Everything else passes through. */
	size_t ulen = strlen(user_dn);
	size_t escaped_cap = ulen * 3 + 1;
	char *escaped = mosquitto_malloc(escaped_cap);
	if(!escaped) return LDAP_Q_OOM;

	size_t w = 0;
	for(size_t i = 0; i < ulen; i++){
		unsigned char c = (unsigned char)user_dn[i];
		switch(c){
			case '*': memcpy(escaped + w, "\\2a", 3); w += 3; break;
			case '(': memcpy(escaped + w, "\\28", 3); w += 3; break;
			case ')': memcpy(escaped + w, "\\29", 3); w += 3; break;
			case '\\': memcpy(escaped + w, "\\5c", 3); w += 3; break;
			case 0:   memcpy(escaped + w, "\\00", 3); w += 3; break;
			default:  escaped[w++] = (char)c;
		}
	}
	escaped[w] = '\0';

	size_t fcap = w + 64;
	char *filter = mosquitto_malloc(fcap);
	if(!filter){
		mosquitto_free(escaped);
		return LDAP_Q_OOM;
	}
	snprintf(filter, fcap, "(&(objectClass=*)(member=%s))", escaped);
	mosquitto_free(escaped);

	char *json_res = NULL;
	enum ldap_query_rc rc = ldap_query_search(ctx, url, bind_dn, bind_pw,
			group_dn, "base", filter, "1.1", &json_res);
	mosquitto_free(filter);

	if(rc != LDAP_Q_OK){
		return rc;
	}

	if(json_res){
		const char *p = json_res;
		while(*p == ' ' || *p == '\t' || *p == '\n') p++;
		*result_out = !(*p == '[' && *(p+1) == ']');
		mosquitto_free(json_res);
	}
	return LDAP_Q_OK;
}
