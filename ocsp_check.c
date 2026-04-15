/*
Copyright (c) 2026 Cedalo Ltd

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

/*
 * OCSP checking for the cert-rego plugin.
 *
 * Design notes:
 *
 *   - All HTTP is done over plain sockets using OpenSSL's own BIO and
 *     OCSP_REQ_CTX helpers. No libcurl, no ad-hoc HTTP parsing.
 *   - Each request runs in non-blocking mode against a select() loop so that
 *     we honour plg->cfg.ocsp_timeout_ms as a hard deadline across connect,
 *     send and receive. DNS resolution via BIO_do_connect is still blocking,
 *     so pathological DNS can exceed the budget — acceptable trade-off.
 *   - We ask the responder to include its certificate in the response and
 *     then verify the response signature against the chain the broker
 *     already verified; no separate trust store is loaded.
 *   - OCSP nonces are enabled. If a responder replies without a nonce we
 *     accept the response but log at warning. Some commercial responders
 *     strip nonces to enable caching.
 *   - Iteration over the chain: ca_chain_check walks every (cert, issuer)
 *     pair in order. The last entry in the verified chain is the trust
 *     anchor; we don't OCSP a self-signed root.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef WIN32
#  include <sys/select.h>
#  include <sys/time.h>
#  include <unistd.h>
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <mosquitto.h>

#include "cert_auth.h"
#include "audit_log.h"  /* audit_log_escape_json_string, reused as a JSON-escape helper */


static long now_ms(void)
{
#ifdef WIN32
	return (long)(GetTickCount64());
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long)(ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
#endif
}


/* Wait on a BIO's underlying fd for the operation it last wanted to retry.
 * Returns 1 if the fd became ready, 0 on timeout, -1 on error. */
static int bio_wait(BIO *bio, long deadline_ms)
{
#ifdef WIN32
	/* Best effort on Windows: no select wait, just let the retry loop spin
	 * until the deadline. In practice mosquitto plugins rarely run on
	 * Windows and this is a first-cut implementation. */
	UNUSED(bio);
	long remaining = deadline_ms - now_ms();
	if(remaining <= 0) return 0;
	Sleep(10);
	return 1;
#else
	int fd = -1;
	long remaining;
	fd_set rfds, wfds;
	struct timeval tv;
	int r;

	if(BIO_get_fd(bio, &fd) < 0 || fd < 0) return -1;

	remaining = deadline_ms - now_ms();
	if(remaining <= 0) return 0;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	if(BIO_should_read(bio)){
		FD_SET(fd, &rfds);
	}else if(BIO_should_write(bio)){
		FD_SET(fd, &wfds);
	}else{
		/* Not a retry we can wait on — let the caller try again immediately. */
		return 1;
	}

	tv.tv_sec = remaining / 1000;
	tv.tv_usec = (remaining % 1000) * 1000;

	r = select(fd + 1, &rfds, &wfds, NULL, &tv);
	if(r < 0){
		if(errno == EINTR) return 1;
		return -1;
	}
	if(r == 0) return 0;
	return 1;
#endif
}


/* Issue a single OCSP request over the given host:port/path and return the
 * parsed OCSP_RESPONSE, or NULL on any failure. The caller owns the response
 * and must free it with OCSP_RESPONSE_free. */
static OCSP_RESPONSE *ocsp_http_send(const char *host, const char *port,
		const char *path, bool use_ssl, OCSP_REQUEST *req, long timeout_ms)
{
	BIO *bio = NULL;
	OCSP_REQ_CTX *ctx = NULL;
	OCSP_RESPONSE *resp = NULL;
	long deadline;
	char host_port[512];
	int rv;

	if(use_ssl){
		/* OCSP-over-HTTPS is rare and would require plumbing a full TLS
		 * client context through here. Not supported in this first pass. */
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: ocsp URL uses https, which is not supported");
		return NULL;
	}

	snprintf(host_port, sizeof(host_port), "%s:%s", host, port);

	bio = BIO_new_connect(host_port);
	if(!bio) return NULL;

	BIO_set_nbio(bio, 1);
	deadline = now_ms() + timeout_ms;

	for(;;){
		long crv = BIO_do_connect(bio);
		if(crv > 0) break;
		if(!BIO_should_retry(bio)){
			mosquitto_log_printf(MOSQ_LOG_WARNING,
					"cert-rego: OCSP connect to %s failed", host_port);
			BIO_free_all(bio);
			return NULL;
		}
		if(bio_wait(bio, deadline) <= 0){
			mosquitto_log_printf(MOSQ_LOG_WARNING,
					"cert-rego: OCSP connect to %s timed out", host_port);
			BIO_free_all(bio);
			return NULL;
		}
	}

	ctx = OCSP_sendreq_new(bio, path, NULL, -1);
	if(!ctx){
		BIO_free_all(bio);
		return NULL;
	}

	if(!OCSP_REQ_CTX_add1_header(ctx, "Host", host)
			|| !OCSP_REQ_CTX_set1_req(ctx, req)){
		OCSP_REQ_CTX_free(ctx);
		BIO_free_all(bio);
		return NULL;
	}

	for(;;){
		rv = OCSP_sendreq_nbio(&resp, ctx);
		if(rv == 1) break;                  /* done */
		if(rv == 0){                        /* retry */
			if(bio_wait(bio, deadline) <= 0){
				mosquitto_log_printf(MOSQ_LOG_WARNING,
						"cert-rego: OCSP request to %s timed out", host_port);
				OCSP_REQ_CTX_free(ctx);
				BIO_free_all(bio);
				return NULL;
			}
			continue;
		}
		/* rv < 0 — protocol error */
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: OCSP request to %s failed", host_port);
		OCSP_REQ_CTX_free(ctx);
		BIO_free_all(bio);
		return NULL;
	}

	OCSP_REQ_CTX_free(ctx);
	BIO_free_all(bio);
	return resp;
}


/* Verify an OCSP response and extract the status for a specific CertID.
 * Returns one of V_OCSP_CERTSTATUS_GOOD/REVOKED/UNKNOWN on success, or -1
 * on any verification failure. *expires_out is set from nextUpdate. The
 * chain parameter is used as the "untrusted" pool for OCSP_basic_verify so
 * that a delegated responder signer present in it can be located; the
 * authoritative trust anchor comes from plg->trust_store. */
static int ocsp_verify_and_extract(struct ca_plugin *plg,
		OCSP_RESPONSE *resp, OCSP_REQUEST *req, OCSP_CERTID *id,
		STACK_OF(X509) *chain, time_t *expires_out)
{
	OCSP_BASICRESP *basic = NULL;
	unsigned long verify_flags = 0;
	int status = -1;
	int cert_status = 0;
	int reason = 0;
	ASN1_GENERALIZEDTIME *this_upd = NULL;
	ASN1_GENERALIZEDTIME *next_upd = NULL;
	ASN1_GENERALIZEDTIME *rev = NULL;
	int response_status;

	*expires_out = 0;

	response_status = OCSP_response_status(resp);
	if(response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: OCSP responder returned non-successful status %d",
				response_status);
		return -1;
	}

	basic = OCSP_response_get1_basic(resp);
	if(!basic){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: OCSP response has no basic response body");
		return -1;
	}

	/* Nonce check: req has a nonce, verify basic echoes it. Accept missing
	 * nonce (OCSP_NONCE_EQUAL == 2) with a warning. */
	{
		int nonce_rv = OCSP_check_nonce(req, basic);
		if(nonce_rv <= 0){
			mosquitto_log_printf(MOSQ_LOG_WARNING,
					"cert-rego: OCSP nonce mismatch or error (%d)", nonce_rv);
			goto out;
		}
		if(nonce_rv == 2){
			mosquitto_log_printf(MOSQ_LOG_DEBUG,
					"cert-rego: OCSP responder did not echo nonce");
		}
	}

	/* The responder certificate may be a delegated signer issued by the
	 * CA — OpenSSL finds it from the untrusted pool we pass in (our chain)
	 * and anchors it against the plugin trust store. We require the
	 * signing cert to carry id-kp-OCSPSigning unless configured otherwise. */
	if(!plg->cfg.ocsp_require_signing_eku){
		verify_flags |= OCSP_NOCHECKS;
	}

	if(OCSP_basic_verify(basic, chain, plg->trust_store, verify_flags) <= 0){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: OCSP response signature verification failed");
		goto out;
	}

	if(!OCSP_resp_find_status(basic, id, &cert_status, &reason,
			&rev, &this_upd, &next_upd)){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: OCSP response did not contain the requested CertID");
		goto out;
	}

	/* thisUpdate must not be in the future, nextUpdate (if present) must not
	 * be in the past. Allow 5 minutes of skew on either side. */
	if(!OCSP_check_validity(this_upd, next_upd, 300L, -1L)){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: OCSP response validity period check failed");
		goto out;
	}

	if(next_upd){
		struct tm tm;
		if(ASN1_TIME_to_tm(next_upd, &tm)){
#ifdef WIN32
			*expires_out = _mkgmtime(&tm);
#else
			*expires_out = timegm(&tm);
#endif
		}
	}

	status = cert_status;

out:
	if(basic) OCSP_BASICRESP_free(basic);
	return status;
}


/* Do one full OCSP round-trip for (cert, issuer) against the AIA URL found
 * on cert. Returns V_OCSP_CERTSTATUS_* on success, -1 on transport failure. */
static int ocsp_check_one(struct ca_plugin *plg,
		X509 *cert, X509 *issuer, STACK_OF(X509) *chain,
		time_t *expires_out)
{
	char *url = NULL;
	char *host = NULL, *port = NULL, *path = NULL;
	int use_ssl = 0;
	OCSP_REQUEST *req = NULL;
	OCSP_RESPONSE *resp = NULL;
	OCSP_CERTID *id = NULL;
	int status = -1;

	*expires_out = 0;

	url = ca_cert_ocsp_url(cert);
	if(!url){
		mosquitto_log_printf(MOSQ_LOG_DEBUG,
				"cert-rego: certificate has no AIA OCSP URL");
		return -1;
	}

	if(!OCSP_parse_url(url, &host, &port, &path, &use_ssl)){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: cannot parse OCSP URL '%s'", url);
		goto out;
	}

	id = OCSP_cert_to_id(NULL, cert, issuer);
	if(!id){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: OCSP_cert_to_id failed");
		goto out;
	}

	req = OCSP_REQUEST_new();
	if(!req) goto out;

	if(!OCSP_request_add0_id(req, id)){
		OCSP_CERTID_free(id);
		goto out;
	}
	id = NULL; /* ownership transferred to req */

	if(!OCSP_request_add1_nonce(req, NULL, -1)){
		goto out;
	}

	resp = ocsp_http_send(host, port, path, use_ssl != 0, req,
			plg->cfg.ocsp_timeout_ms);
	if(!resp){
		goto out;
	}

	/* Re-derive the CertID for verify path — OCSP_resp_find_status needs
	 * its own reference. */
	{
		OCSP_CERTID *vid = OCSP_cert_to_id(NULL, cert, issuer);
		if(vid){
			status = ocsp_verify_and_extract(plg, resp, req, vid, chain, expires_out);
			OCSP_CERTID_free(vid);
		}
	}

out:
	mosquitto_free(url);
	if(host) OPENSSL_free(host);
	if(port) OPENSSL_free(port);
	if(path) OPENSSL_free(path);
	if(req) OCSP_REQUEST_free(req);
	if(resp) OCSP_RESPONSE_free(resp);
	if(id) OCSP_CERTID_free(id);
	return status;
}


/* Is this cert self-signed? If yes it's the trust anchor and we skip OCSP. */
static bool cert_is_self_signed(X509 *c)
{
	return X509_NAME_cmp(X509_get_subject_name(c), X509_get_issuer_name(c)) == 0;
}


/* Is the given X509_verify_cert error one that AIA-chasing might fix? */
static bool verify_err_missing_issuer(int err)
{
	switch(err){
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return true;
		default:
			return false;
	}
}


/* AIA-chase: starting from `from_cert`, walk caIssuers URLs up to depth
 * plg->cfg.aia_fetch_max_depth. Each fetched cert is appended to
 * `untrusted` and taken by reference (caller owns the stack and its
 * certs). Returns the number of certs added. */
static int aia_chase_append(struct ca_plugin *plg, X509 *from_cert,
		STACK_OF(X509) *untrusted)
{
	int added = 0;
	X509 *cur = from_cert;
	for(int d = 0; d < plg->cfg.aia_fetch_max_depth; d++){
		char *url = ca_cert_ca_issuers_url(cur);
		if(!url) break;

		X509 *issuer = aia_fetch_cert(plg, url);
		mosquitto_free(url);
		if(!issuer) break;

		if(!sk_X509_push(untrusted, issuer)){
			X509_free(issuer);
			break;
		}
		added++;
		cur = issuer;  /* walk one more hop using the fetched cert's AIA */

		/* Stop if we've reached a self-signed anchor — pointless to
		 * fetch a self-signed cert's "issuer". */
		if(X509_NAME_cmp(X509_get_subject_name(cur),
				X509_get_issuer_name(cur)) == 0){
			break;
		}
	}
	return added;
}


/* ex_data slot for passing ca_verify_state into the verify callback.
 * Registered lazily on first use; mosquitto's single-threaded callback
 * model means we don't need to serialise this. */
static int g_verify_state_ex_idx = -1;


void ca_verify_state_init(struct ca_verify_state *s)
{
	memset(s, 0, sizeof(*s));
	s->chain_ok = false;
}


const char *ca_verify_err_short(int err_code)
{
	switch(err_code){
		case X509_V_OK:
			return "ok";
		case X509_V_ERR_CERT_HAS_EXPIRED:
			return "expired";
		case X509_V_ERR_CERT_NOT_YET_VALID:
			return "not_yet_valid";
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			return "issuer_unknown";
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return "bad_signature";
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			return "self_signed";
		case X509_V_ERR_CERT_UNTRUSTED:
			return "untrusted";
		case X509_V_ERR_CRL_HAS_EXPIRED:
			return "crl_expired";
		case X509_V_ERR_CERT_REVOKED:
			return "revoked";
		case X509_V_ERR_INVALID_CA:
			return "invalid_ca";
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			return "path_length_exceeded";
		case X509_V_ERR_INVALID_PURPOSE:
			return "invalid_purpose";
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			return "chain_too_long";
		case X509_V_ERR_AKID_SKID_MISMATCH:
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
			return "akid_mismatch";
		default:
			return "other";
	}
}


/* Add a distinct short code to state->distinct_codes if not already
 * present and the array isn't full. */
static void record_distinct_code(struct ca_verify_state *s, const char *code)
{
	if(!code) return;
	for(int i = 0; i < s->distinct_count; i++){
		if(s->distinct_codes[i] == code) return;  /* interned strings */
	}
	if(s->distinct_count < CA_MAX_DISTINCT_CHAIN_ERRS){
		s->distinct_codes[s->distinct_count++] = code;
	}
}


/* OpenSSL verify callback — invoked for every certificate processed and
 * for every failing check. Returning 1 tells OpenSSL to treat the
 * result as ok and keep going, which is how we collect errors without
 * aborting the walk. We stash findings into our state struct.
 *
 * The callback fires multiple times per cert: once per distinct check
 * (signature, validity, purpose, etc.). We dedupe errors per depth so
 * the per-cert list stays short.
 */
static int collecting_verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
	struct ca_verify_state *s = X509_STORE_CTX_get_ex_data(ctx,
			g_verify_state_ex_idx);
	if(!s){
		return 1;  /* no state attached — ignore error, keep going */
	}

	int depth = X509_STORE_CTX_get_error_depth(ctx);
	if(depth < 0 || depth >= CA_MAX_CHAIN_ENTRIES){
		return 1;
	}
	if(depth + 1 > s->cert_count) s->cert_count = depth + 1;

	if(preverify_ok){
		/* Mark this depth as ok only if we haven't already seen an
		 * error for it. A single failing check at this depth dirties
		 * the whole cert. */
		if(s->per_cert[depth].error_count == 0){
			s->per_cert[depth].verify_ok = true;
		}
		return 1;
	}

	/* Record the error. */
	int err = X509_STORE_CTX_get_error(ctx);
	const char *code = ca_verify_err_short(err);
	const char *msg  = X509_verify_cert_error_string(err);

	struct ca_verify_cert_result *r = &s->per_cert[depth];
	/* Dedup within this cert. */
	bool seen = false;
	for(int i = 0; i < r->error_count; i++){
		if(r->short_codes[i] == code){ seen = true; break; }
	}
	if(!seen && r->error_count < CA_MAX_ERRORS_PER_CERT){
		r->short_codes[r->error_count] = code;
		r->messages[r->error_count]    = msg;
		r->error_count++;
	}
	r->verify_ok = false;
	record_distinct_code(s, code);

	return 1;  /* CONTINUE. Rego decides. */
}


int ca_verify_chain(struct ca_plugin *plg,
		X509 *leaf,
		X509_STORE_CTX **ctx_out,
		STACK_OF(X509) **chain_out,
		X509 **anchor_out,
		struct ca_verify_state *state)
{
	X509_STORE_CTX *ctx;
	STACK_OF(X509) *chain;
	STACK_OF(X509) *untrusted = NULL;

	if(ctx_out) *ctx_out = NULL;
	if(chain_out) *chain_out = NULL;
	if(anchor_out) *anchor_out = NULL;
	if(state) ca_verify_state_init(state);

	if(!leaf) return MOSQ_ERR_PLUGIN_DEFER;
	if(!plg->trust_store || !ctx_out || !chain_out || !anchor_out || !state){
		return MOSQ_ERR_AUTH;
	}

	if(g_verify_state_ex_idx < 0){
		g_verify_state_ex_idx = X509_STORE_CTX_get_ex_new_index(
				0, NULL, NULL, NULL, NULL);
		if(g_verify_state_ex_idx < 0) return MOSQ_ERR_NOMEM;
	}

	ctx = X509_STORE_CTX_new();
	if(!ctx) return MOSQ_ERR_NOMEM;

	untrusted = sk_X509_new_null();
	if(!untrusted){
		X509_STORE_CTX_free(ctx);
		return MOSQ_ERR_NOMEM;
	}

	if(!X509_STORE_CTX_init(ctx, plg->trust_store, leaf, untrusted)){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: X509_STORE_CTX_init failed");
		sk_X509_pop_free(untrusted, X509_free);
		X509_STORE_CTX_free(ctx);
		return MOSQ_ERR_NOMEM;
	}

	X509_STORE_CTX_set_ex_data(ctx, g_verify_state_ex_idx, state);
	X509_STORE_CTX_set_verify_cb(ctx, collecting_verify_cb);

	int vrc = X509_verify_cert(ctx);

	/* AIA chase: if the chain hit a "missing issuer" problem AND AIA
	 * fetching is enabled, fetch and retry. Retry uses the SAME state
	 * struct so errors accumulate across retries. */
	if(vrc != 1 && plg->cfg.aia_fetch_enabled && plg->aia_cache){
		int err = X509_STORE_CTX_get_error(ctx);
		if(verify_err_missing_issuer(err)){
			X509 *missing_from = X509_STORE_CTX_get_current_cert(ctx);
			if(!missing_from) missing_from = leaf;

			int added = aia_chase_append(plg, missing_from, untrusted);
			if(added > 0){
				mosquitto_log_printf(MOSQ_LOG_INFO,
						"cert-rego: AIA-fetched %d issuer cert(s), retrying verify",
						added);
				/* Reset the collected state before the retry — the
				 * first pass's "missing issuer" shouldn't stick. */
				ca_verify_state_init(state);
				X509_STORE_CTX_cleanup(ctx);
				if(X509_STORE_CTX_init(ctx, plg->trust_store, leaf, untrusted)){
					X509_STORE_CTX_set_ex_data(ctx, g_verify_state_ex_idx, state);
					X509_STORE_CTX_set_verify_cb(ctx, collecting_verify_cb);
					vrc = X509_verify_cert(ctx);
				}
			}
		}
	}

	/* Whatever chain OpenSSL managed to build — even a partial one. If
	 * verification completely collapsed and there's no chain at all,
	 * we still want Rego to see the leaf in `chain[0]`, so synthesise
	 * a leaf-only stack in that case. */
	chain = X509_STORE_CTX_get0_chain(ctx);
	if(!chain || sk_X509_num(chain) <= 0){
		mosquitto_log_printf(MOSQ_LOG_DEBUG,
				"cert-rego: verify produced no chain, using leaf-only view");
		/* Ensure state records a chain-wide "no_chain" error so Rego
		 * can tell. We'll expose the leaf anyway via a synthetic
		 * single-entry stack held by the ctx via untrusted — but that
		 * would require extra juggling. Simpler: leave chain NULL and
		 * let cert_parse.c emit a chain built from just the leaf. */
		chain = NULL;
		record_distinct_code(state, "no_chain");
		state->chain_ok = false;
	}else{
		state->chain_ok = (vrc == 1) && (state->distinct_count == 0);
		/* If vrc==1 but we still saw errors (callback suppressed them),
		 * chain_ok stays false. */
	}

	sk_X509_pop_free(untrusted, X509_free);

	*ctx_out = ctx;
	*chain_out = chain;
	*anchor_out = (chain && state->chain_ok)
			? sk_X509_value(chain, sk_X509_num(chain) - 1)
			: NULL;

	if(!state->chain_ok){
		mosquitto_log_printf(MOSQ_LOG_DEBUG,
				"cert-rego: chain verification incomplete/failed (%d errors); "
				"Rego will decide",
				state->distinct_count);
	}
	return MOSQ_ERR_SUCCESS;
}


/* Map an OpenSSL OCSP status int to its string label. */
static const char *ocsp_status_label(int status)
{
	switch(status){
		case V_OCSP_CERTSTATUS_GOOD:    return "good";
		case V_OCSP_CERTSTATUS_REVOKED: return "revoked";
		case V_OCSP_CERTSTATUS_UNKNOWN: return "unknown";
		default:                        return "error";
	}
}


/* Append an escaped JSON string to a simple dynamic buffer. Matches the
 * approach used in ldap_query.c and cert_parse.c — we avoid pulling in a
 * JSON library here and keep the shape narrow. */
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


/* Inspect every (cert, issuer) pair in the verified chain, consulting the
 * plugin's OCSP cache first and falling back to a live responder query
 * otherwise. Returns a mosquitto_strdup'd JSON array string of per-cert
 * status objects:
 *
 *   [
 *     {
 *       "depth": 0,
 *       "subject_dn": "...",
 *       "status": "good"|"revoked"|"unknown"|"error"|"skipped_root"|"no_issuer"|"no_aia",
 *       "cached": bool,
 *       "error": string|null
 *     },
 *     ...
 *   ]
 *
 * "skipped_root" marks the self-signed trust anchor (never OCSP-checked).
 * "no_issuer" marks a cert whose issuer is missing from the chain
 * (shouldn't happen with a valid chain but we're defensive).
 * "no_aia" marks a cert with no OCSP responder URL in its AIA extension.
 * "error" covers responder failures — the policy decides strict vs soft.
 *
 * Returns NULL only on out-of-memory. Transport errors become
 * status:"error" entries, not function-level failures, so the policy can
 * distinguish "responder down" from "revoked".
 */
char *ca_ocsp_inspect_json(struct ca_plugin *plg, STACK_OF(X509) *chain)
{
	if(!plg || !chain) return mosquitto_strdup("[]");

	int n = sk_X509_num(chain);
	if(n <= 0) return mosquitto_strdup("[]");

	char *buf = NULL;
	size_t cap = 0, len = 0;

	buf = append_or_free(buf, &cap, &len, "[");
	if(!buf) return NULL;

	bool first = true;
	for(int i = 0; i < n; i++){
		X509 *cert = sk_X509_value(chain, i);
		if(!cert) continue;

		/* Subject DN as a string. Emit one entry regardless of status so the
		 * policy can reason about the whole chain. */
		char subj_buf[512];
		X509_NAME_oneline(X509_get_subject_name(cert), subj_buf, sizeof(subj_buf));

		char *subj_esc = audit_log_escape_json_string(subj_buf);
		if(!subj_esc){ mosquitto_free(buf); return NULL; }

		const char *status_label;
		const char *error_msg = NULL;
		bool cached_flag = false;
		int status = -1;

		if(cert_is_self_signed(cert)){
			status_label = "skipped_root";
		}else if(i + 1 >= n){
			status_label = "no_issuer";
			error_msg = "no issuer in chain";
		}else{
			X509 *issuer = sk_X509_value(chain, i + 1);

			char *aia_url = ca_cert_ocsp_url(cert);
			if(!aia_url){
				status_label = "no_aia";
			}else if(ca_cache_ocsp_lookup(plg->cache, cert, issuer, &status)){
				cached_flag = true;
				status_label = ocsp_status_label(status);
			}else{
				time_t expires = 0;
				status = ocsp_check_one(plg, cert, issuer, chain, &expires);
				if(status < 0){
					status_label = "error";
					error_msg = "ocsp query failed";
				}else{
					status_label = ocsp_status_label(status);
					time_t now = time(NULL);
					(void)expires;
					ca_cache_ocsp_store(plg->cache, cert, issuer, status,
							now + plg->cfg.ocsp_min_refresh_seconds);
				}
			}
			mosquitto_free(aia_url);
		}

		char head[128];
		snprintf(head, sizeof(head),
				"%s{\"depth\":%d,\"subject_dn\":",
				first ? "" : ",", i);
		buf = append_or_free(buf, &cap, &len, head);
		if(!buf){ mosquitto_free(subj_esc); return NULL; }
		buf = append_or_free(buf, &cap, &len, subj_esc);
		mosquitto_free(subj_esc);
		if(!buf) return NULL;

		char tail[256];
		char *err_esc = NULL;
		if(error_msg){
			err_esc = audit_log_escape_json_string(error_msg);
			if(!err_esc){ mosquitto_free(buf); return NULL; }
		}
		snprintf(tail, sizeof(tail),
				",\"status\":\"%s\",\"cached\":%s,\"error\":%s}",
				status_label,
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
