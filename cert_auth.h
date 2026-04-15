/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/
#ifndef CERT_AUTH_H
#define CERT_AUTH_H

/*
 * Shared plugin types and APIs. This header is pure C and is included by
 * every translation unit in the plugin, including the single C++ TU
 * (rego_engine.cpp) that wraps rego-cpp — so no C++ types leak out of here.
 *
 * Design notes as of this revision:
 *
 *   - Passwordless. The plugin does not see, log, or forward a user
 *     password. MQTT CONNECT password field is ignored entirely. The
 *     Rego input doc has no `connect.password`. All external-service
 *     lookups (LDAP, OAuth2 via rego-cpp's http.send, etc.) are driven
 *     by the policy using the cert fields and the service-account
 *     credentials in plugin config.
 *
 *   - Multi-root. `cert_rego_ca_file` accepts a comma-separated list of
 *     PEM bundles, all merged into a single X509_STORE. The Rego input
 *     doc exposes `input.cert.trust_anchor` (subject DN + SHA-256
 *     fingerprint) so policies can dispatch on which root the chain
 *     anchored to.
 *
 *   - Rego is authoritative for subject and identity. The plugin hands
 *     Rego every cert field we can cheaply produce and does not pick a
 *     "primary identity" itself. There is no mosquitto_set_username()
 *     call in the callback — downstream auth plugins, if any, see the
 *     original CONNECT username (which may be empty).
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/safestack.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UNUSED is defined in mosquitto's internal config.h, which is not part of
 * the public headers shipped with libmosquitto-dev. Define it here for
 * external builds so each translation unit can silence unused-parameter
 * warnings the same way the in-tree plugins do. */
#ifndef UNUSED
#  define UNUSED(A) (void)(A)
#endif

/* =========================================================================
 * Configuration structs
 * ========================================================================= */

/* LDAP configuration. Optional — a plugin instance with no allowed_urls
 * still runs fine; any ldap.* call from a policy returns an error (which
 * fail-closed evaluates to deny).
 *
 * The bind DN + password here are service-account credentials used by the
 * plugin to perform searches on behalf of policies. They are NOT
 * user-supplied. In a passwordless deployment this is the only place a
 * password-style credential appears in config. */
struct ca_ldap_config {
	char **allowed_urls;
	size_t allowed_url_count;

	bool require_tls;
	char *ca_file;
	long connect_timeout_ms;
	long op_timeout_ms;
	time_t search_cache_ttl;
};

struct ca_audit_config {
	/* File sink — empty/NULL disables. */
	char *file_path;
	bool fsync_per_line;

	/* Syslog sink. ident defaults to "mosquitto-cert-rego" if empty;
	 * facility default is "authpriv". */
	bool syslog_enabled;
	char *syslog_ident;
	char *syslog_facility;

	/* Threshold filter. INFO by default — emits per-decision lines with
	 * core cert metadata, suitable for production with a relaxed policy.
	 * NOTICE drops allow lines (deny-only). DEBUG adds chain dump, SAN,
	 * custom OIDs, eval timing, and Rego-injected policy notes. */
	int level;              /* enum audit_level value, kept as int to
	                           avoid pulling audit_log.h into every TU. */

	/* Hard per-line cap, bytes. Clamped to [AUDIT_LINE_MIN, AUDIT_LINE_MAX]. */
	size_t line_cap_bytes;

	/* DEBUG-only granular toggles. Each is consulted only when level
	 * is DEBUG; below that they have no effect. */
	bool include_chain_detail;
	int  chain_detail_max_depth;   /* default 8 */
	bool include_san;
	bool include_custom_oids;
	bool include_eval_timing;      /* elapsed_us per decision */
};

struct ca_rego_config {
	char *policy_file;
	char *connect_entrypoint;
	char *acl_entrypoint;
};

/* Plugin-wide configuration. */
struct ca_config {
	/* Trust store: one or more PEM bundles loaded into a single X509_STORE.
	 * The comma-separated string from plugin_opt_cert_rego_ca_file is
	 * split and each entry loaded with X509_STORE_load_locations. */
	char **ca_files;
	size_t ca_file_count;
	char *ca_path;          /* optional, loaded alongside the file list */

	/* OCSP implementation knobs. There is no "enabled" flag and no mode —
	 * whether and how strictly to interpret revocation status is a policy
	 * decision, made in Rego by calling the ocsp.check() host function and
	 * examining the returned per-cert status array. These options only
	 * govern *how* the plugin does its OCSP round-trips when a policy asks. */
	long ocsp_timeout_ms;
	time_t ocsp_min_refresh_seconds;
	bool ocsp_require_signing_eku;

	/* Optional AIA chasing during chain verification. When a client presents
	 * a leaf that doesn't chain to anything in the trust store, and the leaf
	 * (or one of the intermediates presented) carries an AIA caIssuers URL,
	 * the plugin can fetch the referenced CA certificate and retry the
	 * chain build. Disabled by default: fetching arbitrary URLs embedded in
	 * client certs is an SSRF-shaped risk surface. */
	bool aia_fetch_enabled;
	long aia_fetch_timeout_ms;     /* per HTTP GET */
	int aia_fetch_max_depth;       /* max intermediates to chase */
	size_t aia_fetch_max_size;     /* per-response byte cap */
	time_t aia_fetch_cache_ttl;    /* in-memory cert cache TTL */

	/* Optional CRL fetching. CRLs live in the crlDistributionPoints
	 * extension on the cert (distinct from AIA). When the Rego policy
	 * calls crl.check(), the plugin fetches each cert's DP URL, verifies
	 * the CRL's signature against the issuer in the chain, and reports
	 * per-cert revocation. Disabled by default, same SSRF posture as AIA. */
	bool crl_fetch_enabled;
	long crl_fetch_timeout_ms;
	size_t crl_fetch_max_size;
	time_t crl_fetch_cache_ttl;

	struct ca_rego_config rego;
	struct ca_ldap_config ldap;
	struct ca_audit_config audit;

	bool acl_include_payload;
};

/* Opaque forward declarations. */
struct ca_cache;
struct rego_engine;
struct audit_log;
struct aia_cache;
struct crl_cache;

/* Plugin-global state. Exactly one per loaded plugin. */
struct ca_plugin {
	struct ca_config cfg;
	struct ca_cache *cache;
	struct aia_cache *aia_cache;    /* NULL unless cfg.aia_fetch_enabled */
	struct crl_cache *crl_cache;    /* NULL unless cfg.crl_fetch_enabled */
	struct rego_engine *rego;
	struct audit_log *audit;
	X509_STORE *trust_store;
};

/* =========================================================================
 * Cache (cache.c)
 * ========================================================================= */

enum ca_cache_kind {
	CA_CACHE_OCSP = 0,      /* key: issuer name hash || issuer key hash || serial */
	CA_CACHE_LDAP_SEARCH,   /* key: SHA-256 of the full call signature */
};

struct ca_cache *ca_cache_new(void);
void ca_cache_free(struct ca_cache *c);

bool ca_cache_ocsp_lookup(struct ca_cache *c,
		X509 *cert, X509 *issuer,
		int *status_out);

void ca_cache_ocsp_store(struct ca_cache *c,
		X509 *cert, X509 *issuer,
		int status, time_t expires);

char *ca_cache_blob_lookup(struct ca_cache *c,
		enum ca_cache_kind kind,
		const unsigned char *key, size_t key_len);

void ca_cache_blob_store(struct ca_cache *c,
		enum ca_cache_kind kind,
		const unsigned char *key, size_t key_len,
		const char *value_json,
		time_t expires);

/* =========================================================================
 * Chain verification results — surfaced to Rego so policies can inspect
 * them and, if they choose, override specific failure modes (expired
 * intermediate, not-yet-valid leaf, etc.).
 *
 * The plugin NO LONGER denies a connection on chain-verify failure alone.
 * Every cert reaches Rego along with its per-cert verification outcome;
 * Rego is authoritative.
 *
 * Declared here (before cert_parse and ocsp_check APIs) because both
 * modules reference these types.
 * ========================================================================= */

#define CA_MAX_CHAIN_ENTRIES      16
#define CA_MAX_ERRORS_PER_CERT     4
#define CA_MAX_DISTINCT_CHAIN_ERRS 16

/* Per-cert verification outcome. The short_codes and messages arrays
 * point to static storage (our own short codes + OpenSSL's cert-error
 * strings). They are valid for the lifetime of the plugin. */
struct ca_verify_cert_result {
	bool verify_ok;
	int error_count;
	const char *short_codes[CA_MAX_ERRORS_PER_CERT];  /* e.g. "expired" */
	const char *messages[CA_MAX_ERRORS_PER_CERT];     /* human readable */
};

/* Chain-wide verification result. Returned by ca_verify_chain so callers
 * (plugin.c, cert_parse.c) can emit the detail into the Rego input. */
struct ca_verify_state {
	struct ca_verify_cert_result per_cert[CA_MAX_CHAIN_ENTRIES];
	int cert_count;

	/* True iff every cert in the chain verified cleanly. */
	bool chain_ok;

	/* De-duplicated set of short codes across the whole chain, for the
	 * convenience summary field input.cert.chain_errors. */
	const char *distinct_codes[CA_MAX_DISTINCT_CHAIN_ERRS];
	int distinct_count;
};

void ca_verify_state_init(struct ca_verify_state *s);

/* Map an X509_V_ERR_* code to a short policy-friendly name
 * ("expired", "not_yet_valid", "issuer_unknown", "bad_signature",
 *  "self_signed", "untrusted", or "other"). */
const char *ca_verify_err_short(int err_code);


/* =========================================================================
 * Cert parsing (cert_parse.c)
 * ========================================================================= */

/* Extract the first OCSP responder URL found in the AIA extension.
 * Returned buffer must be freed with mosquitto_free. NULL if absent. */
char *ca_cert_ocsp_url(X509 *cert);

/* Extract the first caIssuers URL from the AIA extension — used by the
 * optional AIA-fetch feature to download a missing intermediate when
 * chain verification fails. Returned buffer must be freed with
 * mosquitto_free. NULL if absent. */
char *ca_cert_ca_issuers_url(X509 *cert);

/* Extract every HTTP(S) URL from the crlDistributionPoints extension.
 * Returned is a NULL-terminated array of mosquitto_strdup'd strings;
 * caller frees each element and the array with mosquitto_free. NULL if
 * the extension is absent or contains no URI DPs. *count_out is the
 * number of entries (excluding the terminating NULL). */
char **ca_cert_crl_dp_urls(X509 *cert, size_t *count_out);

/* Build the full cert.* sub-tree of the Rego input document as a JSON
 * string. Emits:
 *   - leaf fields (subject_dn, cn, issuer_dn, serial, fingerprint,
 *     validity, SANs, aia, crl_urls, custom_extensions)
 *   - trust_anchor = last cert in the chain IF verification succeeded,
 *     otherwise null (rego cannot trust an anchor the plugin couldn't
 *     verify to)
 *   - chain_ok  = state->chain_ok summary
 *   - chain_errors = distinct short codes across the whole chain
 *   - chain = array of every cert in the chain, leaf to root, with
 *     per-cert verify_ok + errors alongside the metadata fields
 *
 * If chain is NULL/empty, chain is [] with chain_ok=false and a single
 * chain-wide error ("no_chain").
 *
 * Returned buffer is mosquitto_strdup'd — caller frees with mosquitto_free.
 */
char *ca_cert_input_json(X509 *leaf,
		STACK_OF(X509) *chain,
		const struct ca_verify_state *state);

/* Build the always-on cert metadata fragment for an audit event. Emitted
 * at INFO and above so liberal policies still leave a usable trail.
 *
 * Output is a JSON object body *without* surrounding braces:
 *   "cn":"alice","subject_dn":"...","issuer_dn":"...",
 *   "serial":"...","fingerprint_sha256":"...",
 *   "trust_anchor_fp":"..." (or null when chain_ok=false),
 *   "chain_ok":true|false,"chain_errors":["expired",...]
 *
 * DN strings are truncated to AUDIT_DN_MAX_CHARS to keep the line bounded.
 * Returns NULL on OOM. Caller frees with mosquitto_free. */
char *ca_cert_audit_core_extras(X509 *leaf,
		STACK_OF(X509) *chain,
		const struct ca_verify_state *state);

/* Build the per-cert chain dump fragment for DEBUG-level audit. Emitted
 * only when the operator opted in.
 *
 * Output is a JSON object body *without* surrounding braces:
 *   "chain":[ {"depth":0,"subject_dn":"...","issuer_dn":"...",
 *              "serial":"...","fingerprint_sha256":"...",
 *              "not_before_unix":...,"not_after_unix":...,
 *              "verify_ok":true|false,"errors":["expired",...]}, ... ]
 *   [,"chain_truncated":true]
 *
 * Per-DN truncation uses AUDIT_DN_MAX_CHARS. The chain is capped at
 * `max_depth` entries; if deeper, a "chain_truncated":true sibling key is
 * appended after the array. Returns NULL on OOM. */
char *ca_cert_audit_chain_extras(STACK_OF(X509) *chain,
		const struct ca_verify_state *state,
		int max_depth);

/* Build the SAN dump fragment ("san":{"dns":[...],"email":[...],
 * "uri":[...]}) for DEBUG-level audit. Returns NULL on OOM. */
char *ca_cert_audit_san_extras(X509 *leaf);

/* Build the custom-extensions dump fragment for DEBUG-level audit. Same
 * shape as input.cert.custom_extensions but as an audit body fragment.
 * Returns NULL on OOM. */
char *ca_cert_audit_custom_oid_extras(X509 *leaf);

/* =========================================================================
 * Chain verification and OCSP (ocsp_check.c)
 *
 * The chain is built ONCE per connect:
 *
 *   1. plugin.c calls ca_verify_chain to run X509_verify_cert against the
 *      plugin trust store.
 *
 *   2. plugin.c builds the Rego input doc with trust anchor + full chain
 *      and evaluates the policy.
 *
 *   3. Inside the policy, if Rego wants OCSP it calls the ocsp.check()
 *      host function. That function (registered in rego_engine.cpp) reads
 *      the chain from a per-eval stash set around the rego-cpp eval call
 *      and invokes ca_ocsp_inspect_json to build the result. The plugin
 *      itself has no OCSP flow outside of the host function — whether,
 *      how strictly, and for which certs to check is all policy logic.
 *
 *   4. plugin.c owns the STORE_CTX lifetime — after the callback is done
 *      it calls X509_STORE_CTX_cleanup and X509_STORE_CTX_free.
 * ========================================================================= */

/* Build and inspect the chain. The verification callback collects every
 * per-cert error into `state` rather than aborting on the first one, so
 * Rego sees the full picture regardless of outcome.
 *
 * On success (return MOSQ_ERR_SUCCESS):
 *   - *ctx_out holds a STORE_CTX the caller must X509_STORE_CTX_cleanup
 *     + X509_STORE_CTX_free after it's done reading the chain
 *   - *chain_out is the chain OpenSSL built (may be partial if the root
 *     was never reached). Valid until ctx is freed.
 *   - *anchor_out is the last cert in the chain if chain_ok is true,
 *     otherwise NULL (a verified-anchor concept only applies when the
 *     chain actually terminated at a trust anchor).
 *   - state->chain_ok indicates clean verification; state->per_cert
 *     holds per-cert detail.
 *
 * Returns MOSQ_ERR_PLUGIN_DEFER if leaf is NULL (no cert to inspect).
 * Returns MOSQ_ERR_NOMEM on OOM. Any other outcome — including total
 * chain failure — still reports MOSQ_ERR_SUCCESS with state->chain_ok
 * false, so the caller can let Rego decide. */
int ca_verify_chain(struct ca_plugin *plg,
		X509 *leaf,
		X509_STORE_CTX **ctx_out,
		STACK_OF(X509) **chain_out,
		X509 **anchor_out,
		struct ca_verify_state *state);

/* Inspect every cert in a verified chain against OCSP responders. Returns
 * a mosquitto_strdup'd JSON array string — one object per cert, describing
 * its OCSP status (good/revoked/unknown/error/skipped_root/no_issuer/no_aia),
 * whether the response came from cache, and any error message. The policy
 * decides what combination of statuses constitutes "allow". Returns NULL
 * on out-of-memory. */
char *ca_ocsp_inspect_json(struct ca_plugin *plg, STACK_OF(X509) *chain);

/* Inspect every cert in the verified chain against the CRLs referenced
 * by its crlDistributionPoints extension. Downloads + caches CRLs via
 * crl_fetch. Returns a mosquitto_strdup'd JSON array — one entry per
 * cert with status: good / revoked / expired_crl / unknown / error /
 * skipped_root / no_dp / bad_sig. The policy decides semantics.
 *
 * CRL signatures are verified against the issuing cert within the chain
 * (the cert whose subject matches the CRL's issuer name). If the issuer
 * isn't in the chain, status is "unknown".
 *
 * Requires plg->cfg.crl_fetch_enabled = true; otherwise returns an
 * all-"error" array marking the feature as disabled. Returns NULL only
 * on out-of-memory. */
char *ca_crl_inspect_json(struct ca_plugin *plg, STACK_OF(X509) *chain);

/* =========================================================================
 * AIA fetching (aia_fetch.c)
 *
 * Downloads a CA certificate from an AIA caIssuers URL, caches it in an
 * in-memory keyed by URL, and returns it as a refcount-bumped X509.
 * HTTP and HTTPS only, size-capped, timeout-bounded.
 *
 * This machinery is ONLY engaged during ca_verify_chain when
 * cfg.aia_fetch_enabled is true and the initial chain build fails with a
 * missing-issuer error. It never runs for policies that don't opt in.
 * ========================================================================= */

/* Opaque cert cache used by aia_fetch. Lives on ca_plugin; initialised on
 * plugin load and freed on unload. */
struct aia_cache;
struct aia_cache *aia_cache_new(void);
void aia_cache_free(struct aia_cache *c);

/* Fetch the CA cert at `url` via HTTP/HTTPS, consulting and updating the
 * cache. Returns a new reference on success (caller frees with X509_free),
 * NULL on any failure (logged). Honours plg->cfg.aia_fetch_*. */
X509 *aia_fetch_cert(struct ca_plugin *plg, const char *url);

#ifdef __cplusplus
}
#endif
#endif
