/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/
#ifndef CERT_AUTH_CRL_FETCH_H
#define CERT_AUTH_CRL_FETCH_H

/*
 * CRL fetcher + in-memory cache.
 *
 * CRLs live in the crlDistributionPoints extension (NID_crl_distribution_points,
 * OID 2.5.29.31), not in AIA. Each DP usually carries one or more HTTP
 * URLs pointing at a DER- or PEM-encoded X509_CRL. This module downloads
 * and parses them, caches by URL, and hands out new references.
 *
 * The cache is keyed by URL so two certs under the same issuer share a
 * single CRL download — reducing traffic on a busy PKI where every leaf
 * points at the same CRL. TTL is config-controlled; we also respect the
 * CRL's own nextUpdate as an upper bound when it's set.
 */

#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ca_plugin;

/* Opaque cache type; on the ca_plugin as plg->crl_cache when the feature
 * is enabled. Lifecycle matches aia_cache: created in plugin_init when
 * cfg.crl_fetch_enabled is true, freed in cleanup and on disable-at-reload. */
struct crl_cache;

struct crl_cache *crl_cache_new(void);
void crl_cache_free(struct crl_cache *c);

/*
 * Fetch the CRL at `url`. Returns a fresh reference on success; caller
 * frees with X509_CRL_free. NULL on any error (logged). Honours the
 * plg->cfg.crl_fetch_* options — max_size, timeout_ms, cache_ttl.
 */
X509_CRL *crl_fetch(struct ca_plugin *plg, const char *url);

#ifdef __cplusplus
}
#endif
#endif
