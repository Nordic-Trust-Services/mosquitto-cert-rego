/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

/*
 * CRL check driver: exposed to policies as ocsp.check()'s CRL-equivalent,
 * ocsp_check.c is the mirror module.
 *
 * For each non-root cert in the verified chain:
 *   1. Extract the cert's crlDistributionPoints URLs.
 *   2. Fetch + cache the first usable CRL via crl_fetch.c.
 *   3. Locate the cert's issuer in the chain and verify the CRL's
 *      signature using the issuer's public key.
 *   4. Check if the cert's serial is in the CRL's revoked list.
 *   5. Check the CRL's nextUpdate against now — staleness is exposed
 *      as "expired_crl" so the policy can decide strict vs soft.
 *
 * The CRL is cached by URL; the issuer-public-key lookup and signature
 * verification happen on every evaluation against the cached CRL.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mosquitto.h>

#include "cert_auth.h"
#include "audit_log.h"
#include "crl_fetch.h"


static bool crl_is_current(X509_CRL *crl)
{
	const ASN1_TIME *nxt = X509_CRL_get0_nextUpdate(crl);
	if(!nxt) return true;  /* lastUpdate-only CRLs are rare but allowed */
	return X509_cmp_current_time(nxt) > 0;
}


/* Find the cert in `chain` whose subject DN matches `issuer_name`. Used
 * to locate the issuing cert for CRL signature verification. */
static X509 *find_issuer_in_chain(STACK_OF(X509) *chain, X509_NAME *issuer_name)
{
	if(!issuer_name) return NULL;
	int n = sk_X509_num(chain);
	for(int i = 0; i < n; i++){
		X509 *c = sk_X509_value(chain, i);
		if(!c) continue;
		if(X509_NAME_cmp(X509_get_subject_name(c), issuer_name) == 0){
			return c;
		}
	}
	return NULL;
}


static char *append_or_free(char *buf, size_t *cap, size_t *len, const char *s)
{
	size_t add = strlen(s);
	if(*len + add + 1 > *cap){
		size_t ncap = *cap ? *cap * 2 : 512;
		while(ncap < *len + add + 1) ncap *= 2;
		char *nb = mosquitto_realloc(buf, ncap);
		if(!nb){ mosquitto_free(buf); return NULL; }
		buf = nb;
		*cap = ncap;
	}
	memcpy(buf + *len, s, add);
	*len += add;
	buf[*len] = '\0';
	return buf;
}


/* Check one (cert, issuer) pair against its CRL. Fills *status_out and
 * *err_out (err_out may be NULL). Writes a cache-hit flag to *cached_out.
 * Returns true if the status is authoritative (good or revoked), false
 * otherwise. */
static bool check_one(struct ca_plugin *plg,
		X509 *cert,
		X509 *issuer,
		const char **status_out,
		const char **err_out,
		bool *cached_out)
{
	*status_out = "error";
	*err_out = NULL;
	*cached_out = false;

	size_t n_urls = 0;
	char **urls = ca_cert_crl_dp_urls(cert, &n_urls);
	if(!urls || n_urls == 0){
		if(urls) mosquitto_free(urls);
		*status_out = "no_dp";
		return false;
	}

	X509_CRL *crl = NULL;
	const char *used_url = NULL;
	for(size_t i = 0; i < n_urls; i++){
		/* crl_fetch consults cache first — if the URL was fetched
		 * earlier the cache hit returns a new reference. */
		crl = crl_fetch(plg, urls[i]);
		if(crl){ used_url = urls[i]; break; }
	}
	(void)used_url;
	bool from_cache = false;
	if(crl){
		/* Heuristic: a repeat of the same URL within the plugin's TTL
		 * is a cache hit. crl_fetch itself doesn't signal this so we
		 * probe once via a second lookup — acceptable for an audit
		 * flag only. */
		X509_CRL *probe = crl_fetch(plg, used_url);
		if(probe){
			from_cache = true;
			X509_CRL_free(probe);
		}
	}

	for(size_t i = 0; i < n_urls; i++) mosquitto_free(urls[i]);
	mosquitto_free(urls);

	if(!crl){
		*status_out = "error";
		*err_out = "fetch failed";
		return false;
	}
	*cached_out = from_cache;

	/* Signature verification against the issuer's public key. If the
	 * issuer is not in the chain at all, we can't verify and the status
	 * is unknown. */
	if(!issuer){
		X509_CRL_free(crl);
		*status_out = "unknown";
		*err_out = "issuer not in chain";
		return false;
	}

	EVP_PKEY *pkey = X509_get_pubkey(issuer);
	if(!pkey){
		X509_CRL_free(crl);
		*status_out = "error";
		*err_out = "issuer has no public key";
		return false;
	}
	int vrc = X509_CRL_verify(crl, pkey);
	EVP_PKEY_free(pkey);
	if(vrc != 1){
		X509_CRL_free(crl);
		*status_out = "bad_sig";
		*err_out = "crl signature verification failed";
		return false;
	}

	if(!crl_is_current(crl)){
		*status_out = "expired_crl";
		*err_out = "crl nextUpdate is in the past";
		/* Still check revocation — the CRL may contain useful revoked
		 * entries even if stale. But we label the status so strict
		 * policies can reject. */
	}else{
		*status_out = "good"; /* provisional — may be overwritten below */
	}

	/* Is the cert serial in the revoked list? */
	X509_REVOKED *revoked = NULL;
	int rc = X509_CRL_get0_by_cert(crl, &revoked, cert);
	X509_CRL_free(crl);

	if(rc == 1 && revoked){
		*status_out = "revoked";
		return true;
	}
	/* rc == 0: not revoked. rc == 2: match by serial, mismatched issuer
	 * — treat as unknown since the CRL doesn't cover this issuer. */
	if(rc == 2){
		*status_out = "unknown";
		*err_out = "crl issuer mismatch";
		return false;
	}
	return true;
}


char *ca_crl_inspect_json(struct ca_plugin *plg, STACK_OF(X509) *chain)
{
	if(!plg || !chain) return mosquitto_strdup("[]");

	int n = sk_X509_num(chain);
	if(n <= 0) return mosquitto_strdup("[]");

	if(!plg->cfg.crl_fetch_enabled){
		/* The feature is off. Emit an all-error array so policies that
		 * call crl.check() get a deterministic (and deny-producing)
		 * response rather than silent success. */
		char *buf = NULL;
		size_t cap = 0, len = 0;
		buf = append_or_free(buf, &cap, &len, "[");
		if(!buf) return NULL;
		bool first = true;
		for(int i = 0; i < n; i++){
			char item[512];
			snprintf(item, sizeof(item),
					"%s{\"depth\":%d,\"subject_dn\":\"\",\"status\":\"error\","
					"\"cached\":false,\"error\":\"crl_fetch_disabled\"}",
					first ? "" : ",", i);
			buf = append_or_free(buf, &cap, &len, item);
			if(!buf) return NULL;
			first = false;
		}
		buf = append_or_free(buf, &cap, &len, "]");
		return buf;
	}

	char *buf = NULL;
	size_t cap = 0, len = 0;
	buf = append_or_free(buf, &cap, &len, "[");
	if(!buf) return NULL;
	bool first = true;

	for(int i = 0; i < n; i++){
		X509 *cert = sk_X509_value(chain, i);
		if(!cert) continue;

		char subj_buf[512];
		X509_NAME_oneline(X509_get_subject_name(cert), subj_buf, sizeof(subj_buf));
		char *subj_esc = audit_log_escape_json_string(subj_buf);
		if(!subj_esc){ mosquitto_free(buf); return NULL; }

		const char *status = "skipped_root";
		const char *err = NULL;
		bool cached_flag = false;

		if(X509_NAME_cmp(X509_get_subject_name(cert),
				X509_get_issuer_name(cert)) == 0){
			status = "skipped_root";
		}else{
			X509 *issuer = find_issuer_in_chain(chain,
					X509_get_issuer_name(cert));
			(void)check_one(plg, cert, issuer, &status, &err, &cached_flag);
		}

		char *err_esc = NULL;
		if(err){
			err_esc = audit_log_escape_json_string(err);
			if(!err_esc){ mosquitto_free(subj_esc); mosquitto_free(buf); return NULL; }
		}

		char head[64];
		snprintf(head, sizeof(head),
				"%s{\"depth\":%d,\"subject_dn\":", first ? "" : ",", i);
		buf = append_or_free(buf, &cap, &len, head);
		if(!buf){ mosquitto_free(subj_esc); mosquitto_free(err_esc); return NULL; }
		buf = append_or_free(buf, &cap, &len, subj_esc);
		mosquitto_free(subj_esc);
		if(!buf){ mosquitto_free(err_esc); return NULL; }

		char tail[256];
		snprintf(tail, sizeof(tail),
				",\"status\":\"%s\",\"cached\":%s,\"error\":%s}",
				status,
				cached_flag ? "true" : "false",
				err_esc ? err_esc : "null");
		mosquitto_free(err_esc);
		buf = append_or_free(buf, &cap, &len, tail);
		if(!buf) return NULL;
		first = false;
	}

	buf = append_or_free(buf, &cap, &len, "]");
	return buf;
}
