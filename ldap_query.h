/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/
#ifndef CERT_AUTH_LDAP_QUERY_H
#define CERT_AUTH_LDAP_QUERY_H

/*
 * LDAP operations exposed to Rego policies through rego_engine.cpp.
 *
 * Every function here is the C implementation of a Rego custom builtin:
 *   ldap.search(url, bind_dn, bind_pw, base,
 *               scope, filter, attrs)          -> [object]
 *   ldap.exists(url, bind_dn, bind_pw, base, filter) -> bool
 *   ldap.is_member(url, bind_dn, bind_pw, group_dn, user_dn) -> bool
 *
 * This plugin is passwordless: there is no ldap.login operation. All
 * binds use the plugin's service-account credentials from config; no
 * user-supplied password ever reaches libldap.
 *
 * The plugin enforces a URL whitelist and (optionally) a require_tls policy
 * inside these functions, so policy authors cannot use the LDAP primitives
 * to reach arbitrary endpoints.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ca_ldap_config;
struct ca_cache;
struct audit_log;

/* Context passed to every call — lets us keep the API stateless from the
 * Rego engine's perspective while still reaching plugin-wide state (whitelist,
 * cache, audit log) without globals inside ldap_query.c itself. */
struct ldap_ctx {
	const struct ca_ldap_config *cfg;
	struct ca_cache *cache;          /* may be NULL -> no caching */
	struct audit_log *audit;         /* may be NULL -> no audit */
};

/* Return codes for the operational API. Distinct from the policy-level
 * bool so the rego_engine wrapper can distinguish "LDAP said no" from
 * "LDAP errored and we failed closed". */
enum ldap_query_rc {
	LDAP_Q_OK = 0,
	LDAP_Q_DENIED = 1,        /* policy check failed (bad cred, no match) */
	LDAP_Q_URL_NOT_ALLOWED,   /* URL not in whitelist */
	LDAP_Q_TLS_REQUIRED,      /* require_tls on and url is ldap:// */
	LDAP_Q_CONNECT_FAILED,    /* socket/TLS handshake failed */
	LDAP_Q_TIMEOUT,
	LDAP_Q_BIND_FAILED,
	LDAP_Q_SEARCH_FAILED,
	LDAP_Q_OOM,
	LDAP_Q_INVAL,
};

const char *ldap_query_rc_str(enum ldap_query_rc rc);

/* ldap.search — returns LDAP_Q_OK on success with *result_json_out set to a
 * mosquitto_strdup'd JSON array of entry objects. Each entry is shaped as:
 *   {"dn": "...", "attrs": {"cn": ["alice"], "memberOf": ["cn=x,..."]}}
 *
 * scope: "base" | "one" | "sub".
 * attrs: comma-separated attribute names, or NULL/empty to request all.
 * Caller owns and must free *result_json_out with mosquitto_free.
 *
 * May consult the cache if ctx->cfg->search_cache_ttl > 0.
 */
enum ldap_query_rc ldap_query_search(
		struct ldap_ctx *ctx,
		const char *url,
		const char *bind_dn,
		const char *bind_pw,
		const char *base_dn,
		const char *scope,
		const char *filter,
		const char *attrs,
		char **result_json_out);

/* ldap.exists — shortcut for "does a search of (base, filter) return at
 * least one entry?". Returns LDAP_Q_OK with *result_out filled. */
enum ldap_query_rc ldap_query_exists(
		struct ldap_ctx *ctx,
		const char *url,
		const char *bind_dn,
		const char *bind_pw,
		const char *base_dn,
		const char *filter,
		bool *result_out);

/* ldap.is_member — checks that group_dn exists and has member=user_dn. */
enum ldap_query_rc ldap_query_is_member(
		struct ldap_ctx *ctx,
		const char *url,
		const char *bind_dn,
		const char *bind_pw,
		const char *group_dn,
		const char *user_dn,
		bool *result_out);

#ifdef __cplusplus
}
#endif
#endif
