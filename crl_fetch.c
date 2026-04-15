/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

/*
 * CRL fetcher + in-memory cache.
 *
 * Mirrors aia_fetch.c: HTTP transport comes from http_fetch.c, this file
 * is only the cache + parse layer. Separate cache because X509 and
 * X509_CRL have different lifecycle + refcount families.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <mosquitto.h>

#include "cert_auth.h"
#include "crl_fetch.h"
#include "http_fetch.h"


#define CRL_CACHE_MAX 128
#define CRL_KEY_LEN   32  /* SHA-256 of URL */


struct crl_entry {
	struct crl_entry *next;
	unsigned char key[CRL_KEY_LEN];
	X509_CRL *crl;
	time_t expires;
};


struct crl_cache {
	struct crl_entry *head;
	size_t count;
};


struct crl_cache *crl_cache_new(void)
{
	return mosquitto_calloc(1, sizeof(struct crl_cache));
}


void crl_cache_free(struct crl_cache *c)
{
	if(!c) return;
	struct crl_entry *e, *n;
	for(e = c->head; e; e = n){
		n = e->next;
		if(e->crl) X509_CRL_free(e->crl);
		mosquitto_free(e);
	}
	mosquitto_free(c);
}


static void url_key(const char *url, unsigned char out[CRL_KEY_LEN])
{
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	unsigned int mdlen = CRL_KEY_LEN;
	EVP_DigestInit_ex(md, EVP_sha256(), NULL);
	EVP_DigestUpdate(md, url, strlen(url));
	EVP_DigestFinal_ex(md, out, &mdlen);
	EVP_MD_CTX_free(md);
}


static X509_CRL *cache_lookup(struct crl_cache *c, const char *url)
{
	if(!c || !url) return NULL;
	unsigned char key[CRL_KEY_LEN];
	url_key(url, key);
	time_t now = time(NULL);
	for(struct crl_entry *e = c->head; e; e = e->next){
		if(memcmp(e->key, key, CRL_KEY_LEN) != 0) continue;
		if(e->expires != 0 && e->expires <= now) return NULL;
		X509_CRL_up_ref(e->crl);
		return e->crl;
	}
	return NULL;
}


static void cache_evict_one(struct crl_cache *c)
{
	struct crl_entry **cursor, **oldest = NULL;
	time_t oldest_exp = 0;
	time_t now = time(NULL);

	cursor = &c->head;
	while(*cursor){
		if((*cursor)->expires != 0 && (*cursor)->expires <= now){
			struct crl_entry *v = *cursor;
			*cursor = v->next;
			X509_CRL_free(v->crl);
			mosquitto_free(v);
			c->count--;
			return;
		}
		cursor = &(*cursor)->next;
	}
	cursor = &c->head;
	while(*cursor){
		if(!oldest || (*cursor)->expires < oldest_exp){
			oldest = cursor;
			oldest_exp = (*cursor)->expires;
		}
		cursor = &(*cursor)->next;
	}
	if(oldest){
		struct crl_entry *v = *oldest;
		*oldest = v->next;
		X509_CRL_free(v->crl);
		mosquitto_free(v);
		c->count--;
	}
}


static void cache_store(struct crl_cache *c, const char *url, X509_CRL *crl, time_t expires)
{
	if(!c || !url || !crl) return;
	unsigned char key[CRL_KEY_LEN];
	url_key(url, key);

	for(struct crl_entry *e = c->head; e; e = e->next){
		if(memcmp(e->key, key, CRL_KEY_LEN) == 0){
			X509_CRL_free(e->crl);
			X509_CRL_up_ref(crl);
			e->crl = crl;
			e->expires = expires;
			return;
		}
	}

	while(c->count >= CRL_CACHE_MAX) cache_evict_one(c);

	struct crl_entry *e = mosquitto_calloc(1, sizeof(*e));
	if(!e) return;
	memcpy(e->key, key, CRL_KEY_LEN);
	X509_CRL_up_ref(crl);
	e->crl = crl;
	e->expires = expires;
	e->next = c->head;
	c->head = e;
	c->count++;
}


/* Try DER first, then PEM. */
static X509_CRL *parse_crl(const unsigned char *body, size_t len)
{
	const unsigned char *p = body;
	X509_CRL *der = d2i_X509_CRL(NULL, &p, (long)len);
	if(der) return der;

	BIO *mem = BIO_new_mem_buf(body, (int)len);
	if(!mem) return NULL;
	X509_CRL *pem = PEM_read_bio_X509_CRL(mem, NULL, NULL, NULL);
	BIO_free(mem);
	return pem;
}


/* Derive the effective cache expiry by intersecting the configured TTL
 * with the CRL's nextUpdate. A CRL whose nextUpdate is in the past is
 * still cached briefly so the same bad responder doesn't get hammered
 * for every evaluation. */
static time_t crl_effective_expiry(X509_CRL *crl, time_t cfg_ttl)
{
	time_t now = time(NULL);
	time_t ttl_expiry = now + cfg_ttl;

	const ASN1_TIME *nxt = X509_CRL_get0_nextUpdate(crl);
	if(!nxt) return ttl_expiry;

	struct tm tm;
	if(!ASN1_TIME_to_tm(nxt, &tm)) return ttl_expiry;
#ifdef WIN32
	time_t next_update = _mkgmtime(&tm);
#else
	time_t next_update = timegm(&tm);
#endif
	/* Clamp — don't cache past the responder's stated nextUpdate, and
	 * don't cache past our own ttl, whichever is tighter. */
	if(next_update > 0 && next_update < ttl_expiry) return next_update;
	return ttl_expiry;
}


X509_CRL *crl_fetch(struct ca_plugin *plg, const char *url)
{
	if(!plg || !plg->cfg.crl_fetch_enabled || !plg->crl_cache || !url){
		return NULL;
	}

	X509_CRL *cached = cache_lookup(plg->crl_cache, url);
	if(cached) return cached;

	unsigned char *body = NULL;
	size_t body_len = 0;
	enum http_fetch_rc hrc = http_get(url,
			plg->cfg.crl_fetch_max_size,
			plg->cfg.crl_fetch_timeout_ms,
			&body, &body_len);
	if(hrc != HTTP_FETCH_OK){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: crl: fetch %s: %s",
				url, http_fetch_rc_str(hrc));
		return NULL;
	}

	X509_CRL *crl = parse_crl(body, body_len);
	mosquitto_free(body);

	if(!crl){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: crl: body is neither DER nor PEM CRL for %s", url);
		return NULL;
	}

	cache_store(plg->crl_cache, url, crl,
			crl_effective_expiry(crl, plg->cfg.crl_fetch_cache_ttl));
	mosquitto_log_printf(MOSQ_LOG_INFO,
			"cert-rego: crl: fetched CRL from %s", url);
	return crl;
}
