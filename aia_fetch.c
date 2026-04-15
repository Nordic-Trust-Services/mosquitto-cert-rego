/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

/*
 * AIA caIssuers fetcher.
 *
 * When a client cert chain is missing an intermediate that the plugin
 * trust store doesn't hold, the chain verification fails. If AIA
 * fetching is enabled, the plugin walks the caIssuers URLs present on
 * the leaf / presented intermediates, downloads the referenced CA cert,
 * and retries the chain build.
 *
 * This module is the cache + parse layer. HTTP transport (schemes,
 * size cap, timeout, TLS) lives in http_fetch.c and is shared with
 * crl_fetch.c.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <mosquitto.h>

#include "cert_auth.h"
#include "http_fetch.h"


#define AIA_CACHE_MAX 256
#define AIA_KEY_LEN   32  /* SHA-256 */

struct aia_entry {
	struct aia_entry *next;
	unsigned char key[AIA_KEY_LEN];
	X509 *cert;
	time_t expires;
};

struct aia_cache {
	struct aia_entry *head;
	size_t count;
};


struct aia_cache *aia_cache_new(void)
{
	return mosquitto_calloc(1, sizeof(struct aia_cache));
}


void aia_cache_free(struct aia_cache *c)
{
	if(!c) return;
	struct aia_entry *e, *n;
	for(e = c->head; e; e = n){
		n = e->next;
		if(e->cert) X509_free(e->cert);
		mosquitto_free(e);
	}
	mosquitto_free(c);
}


static void url_key(const char *url, unsigned char out[AIA_KEY_LEN])
{
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	unsigned int mdlen = AIA_KEY_LEN;
	EVP_DigestInit_ex(md, EVP_sha256(), NULL);
	EVP_DigestUpdate(md, url, strlen(url));
	EVP_DigestFinal_ex(md, out, &mdlen);
	EVP_MD_CTX_free(md);
}


static X509 *cache_lookup(struct aia_cache *c, const char *url)
{
	if(!c || !url) return NULL;
	unsigned char key[AIA_KEY_LEN];
	url_key(url, key);

	time_t now = time(NULL);
	for(struct aia_entry *e = c->head; e; e = e->next){
		if(memcmp(e->key, key, AIA_KEY_LEN) != 0) continue;
		if(e->expires != 0 && e->expires <= now) return NULL;
		X509_up_ref(e->cert);
		return e->cert;
	}
	return NULL;
}


static void cache_evict_one(struct aia_cache *c)
{
	struct aia_entry **cursor, **oldest = NULL;
	time_t oldest_exp = 0;
	time_t now = time(NULL);

	cursor = &c->head;
	while(*cursor){
		if((*cursor)->expires != 0 && (*cursor)->expires <= now){
			struct aia_entry *v = *cursor;
			*cursor = v->next;
			X509_free(v->cert);
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
		struct aia_entry *v = *oldest;
		*oldest = v->next;
		X509_free(v->cert);
		mosquitto_free(v);
		c->count--;
	}
}


static void cache_store(struct aia_cache *c, const char *url, X509 *cert, time_t expires)
{
	if(!c || !url || !cert) return;
	unsigned char key[AIA_KEY_LEN];
	url_key(url, key);

	for(struct aia_entry *e = c->head; e; e = e->next){
		if(memcmp(e->key, key, AIA_KEY_LEN) == 0){
			X509_free(e->cert);
			X509_up_ref(cert);
			e->cert = cert;
			e->expires = expires;
			return;
		}
	}

	while(c->count >= AIA_CACHE_MAX) cache_evict_one(c);

	struct aia_entry *e = mosquitto_calloc(1, sizeof(*e));
	if(!e) return;
	memcpy(e->key, key, AIA_KEY_LEN);
	X509_up_ref(cert);
	e->cert = cert;
	e->expires = expires;
	e->next = c->head;
	c->head = e;
	c->count++;
}


/* Try DER first, then PEM. Returns NULL if neither form yields a cert. */
static X509 *parse_cert(const unsigned char *body, size_t len)
{
	const unsigned char *p = body;
	X509 *der_cert = d2i_X509(NULL, &p, (long)len);
	if(der_cert) return der_cert;

	BIO *mem = BIO_new_mem_buf(body, (int)len);
	if(!mem) return NULL;
	X509 *pem_cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
	BIO_free(mem);
	return pem_cert;
}


X509 *aia_fetch_cert(struct ca_plugin *plg, const char *url)
{
	if(!plg || !plg->cfg.aia_fetch_enabled || !plg->aia_cache || !url){
		return NULL;
	}

	X509 *cached = cache_lookup(plg->aia_cache, url);
	if(cached) return cached;

	unsigned char *body = NULL;
	size_t body_len = 0;
	enum http_fetch_rc hrc = http_get(url,
			plg->cfg.aia_fetch_max_size,
			plg->cfg.aia_fetch_timeout_ms,
			&body, &body_len);
	if(hrc != HTTP_FETCH_OK){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: aia: fetch %s: %s",
				url, http_fetch_rc_str(hrc));
		return NULL;
	}

	X509 *cert = parse_cert(body, body_len);
	mosquitto_free(body);

	if(!cert){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: aia: body is neither DER nor PEM cert for %s", url);
		return NULL;
	}

	cache_store(plg->aia_cache, url, cert,
			time(NULL) + plg->cfg.aia_fetch_cache_ttl);
	mosquitto_log_printf(MOSQ_LOG_INFO,
			"cert-rego: aia: fetched CA from %s", url);
	return cert;
}
