/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

/*
 * In-memory response cache.
 *
 * Two kinds of entries live in the same cache object:
 *
 *   CA_CACHE_OCSP        — keyed by the OCSP CertID triple (issuer name hash,
 *                          issuer key hash, serial). Stores a V_OCSP_CERTSTATUS_*
 *                          integer. Refresh is throttled via the plugin's
 *                          ocsp_min_refresh_seconds floor — see ocsp_check.c
 *                          for the policy.
 *
 *   CA_CACHE_LDAP_SEARCH — keyed by a caller-provided opaque byte string
 *                          (the caller should pass a SHA-256 of the full
 *                          search-call signature including bind credentials
 *                          so caches for different binds cannot collide).
 *                          Stores a JSON string (the serialised search
 *                          result). Expiry comes from ldap_query_search's
 *                          ctx->cfg->search_cache_ttl, not the OCSP floor.
 *
 * Each kind has its own linked list. No hash index — this cache is sized
 * for fleets of low thousands of clients and short-TTL entries, where the
 * linked-list walk cost is dwarfed by network round-trips. The plugin runs
 * on mosquitto's single main loop thread, so there is no locking.
 *
 * Memory budgeting:
 *   CA_CACHE_MAX_OCSP_ENTRIES   — hard cap; eviction prefers expired, then
 *                                 earliest-expires.
 *   CA_CACHE_MAX_LDAP_ENTRIES   — separate cap; same eviction policy.
 *   Blob values are copied on store with mosquitto_strdup; the caller is
 *   free to free its own source string immediately after store.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <mosquitto.h>

#include "cert_auth.h"

#define CA_CACHE_NAME_HASH_LEN     20
#define CA_CACHE_KEY_HASH_LEN      20
#define CA_CACHE_SERIAL_MAX        64
#define CA_CACHE_BLOB_KEY_MAX      32   /* exactly one SHA-256 */
#define CA_CACHE_MAX_OCSP_ENTRIES  4096
#define CA_CACHE_MAX_LDAP_ENTRIES  4096


struct ocsp_entry {
	struct ocsp_entry *next;
	time_t expires;
	int status;                /* V_OCSP_CERTSTATUS_* */
	uint8_t name_hash[CA_CACHE_NAME_HASH_LEN];
	uint8_t key_hash[CA_CACHE_KEY_HASH_LEN];
	uint8_t serial[CA_CACHE_SERIAL_MAX];
	int serial_len;
};


struct blob_entry {
	struct blob_entry *next;
	time_t expires;
	enum ca_cache_kind kind;
	uint8_t key[CA_CACHE_BLOB_KEY_MAX];
	size_t key_len;
	char *value;               /* mosquitto_strdup'd, freed on evict */
};


struct ca_cache {
	struct ocsp_entry *ocsp_head;
	size_t ocsp_count;
	struct blob_entry *blob_head;
	size_t blob_count;
};


struct ca_cache *ca_cache_new(void)
{
	return mosquitto_calloc(1, sizeof(struct ca_cache));
}


void ca_cache_free(struct ca_cache *c)
{
	if(!c) return;

	struct ocsp_entry *oe, *on;
	for(oe = c->ocsp_head; oe; oe = on){
		on = oe->next;
		mosquitto_free(oe);
	}

	struct blob_entry *be, *bn;
	for(be = c->blob_head; be; be = bn){
		bn = be->next;
		mosquitto_free(be->value);
		mosquitto_free(be);
	}

	mosquitto_free(c);
}


/* ---- OCSP key computation --------------------------------------------- */

static int ocsp_key(X509 *cert, X509 *issuer,
		uint8_t name_hash[CA_CACHE_NAME_HASH_LEN],
		uint8_t key_hash[CA_CACHE_KEY_HASH_LEN],
		uint8_t *serial_out, int serial_max, int *serial_len_out)
{
	X509_NAME *iname;
	ASN1_BIT_STRING *ikey;
	ASN1_INTEGER *sn;
	unsigned int md_len;
	unsigned char name_der[4096];
	unsigned char *p;
	int name_der_len;

	iname = X509_get_subject_name(issuer);
	if(!iname) return -1;

	p = name_der;
	name_der_len = i2d_X509_NAME(iname, NULL);
	if(name_der_len <= 0 || name_der_len > (int)sizeof(name_der)) return -1;
	name_der_len = i2d_X509_NAME(iname, &p);
	if(name_der_len <= 0) return -1;

	md_len = CA_CACHE_NAME_HASH_LEN;
	if(!EVP_Digest(name_der, (size_t)name_der_len, name_hash, &md_len,
			EVP_sha1(), NULL)){
		return -1;
	}

	ikey = X509_get0_pubkey_bitstr(issuer);
	if(!ikey) return -1;
	md_len = CA_CACHE_KEY_HASH_LEN;
	if(!EVP_Digest(ASN1_STRING_get0_data(ikey),
			(size_t)ASN1_STRING_length(ikey),
			key_hash, &md_len, EVP_sha1(), NULL)){
		return -1;
	}

	sn = X509_get_serialNumber(cert);
	if(!sn) return -1;
	if(sn->length <= 0 || sn->length > serial_max) return -1;
	memcpy(serial_out, sn->data, (size_t)sn->length);
	*serial_len_out = sn->length;

	return 0;
}


/* ---- OCSP lookup / store ---------------------------------------------- */

bool ca_cache_ocsp_lookup(struct ca_cache *c,
		X509 *cert, X509 *issuer,
		int *status_out)
{
	struct ocsp_entry *e;
	uint8_t name_hash[CA_CACHE_NAME_HASH_LEN];
	uint8_t key_hash[CA_CACHE_KEY_HASH_LEN];
	uint8_t serial[CA_CACHE_SERIAL_MAX];
	int serial_len = 0;
	time_t now;

	if(!c || !cert || !issuer || !status_out) return false;
	if(ocsp_key(cert, issuer, name_hash, key_hash, serial,
			CA_CACHE_SERIAL_MAX, &serial_len) != 0){
		return false;
	}

	now = time(NULL);
	for(e = c->ocsp_head; e; e = e->next){
		if(e->serial_len != serial_len) continue;
		if(memcmp(e->name_hash, name_hash, CA_CACHE_NAME_HASH_LEN) != 0) continue;
		if(memcmp(e->key_hash, key_hash, CA_CACHE_KEY_HASH_LEN) != 0) continue;
		if(memcmp(e->serial, serial, (size_t)serial_len) != 0) continue;

		if(e->expires != 0 && e->expires <= now) return false;
		*status_out = e->status;
		return true;
	}
	return false;
}


static void ocsp_evict_one(struct ca_cache *c)
{
	struct ocsp_entry **cursor, **oldest_link = NULL;
	time_t oldest_exp = 0;
	time_t now = time(NULL);

	cursor = &c->ocsp_head;
	while(*cursor){
		if((*cursor)->expires != 0 && (*cursor)->expires <= now){
			struct ocsp_entry *v = *cursor;
			*cursor = v->next;
			mosquitto_free(v);
			c->ocsp_count--;
			return;
		}
		cursor = &(*cursor)->next;
	}

	cursor = &c->ocsp_head;
	while(*cursor){
		if(oldest_link == NULL || (*cursor)->expires < oldest_exp){
			oldest_link = cursor;
			oldest_exp = (*cursor)->expires;
		}
		cursor = &(*cursor)->next;
	}
	if(oldest_link){
		struct ocsp_entry *v = *oldest_link;
		*oldest_link = v->next;
		mosquitto_free(v);
		c->ocsp_count--;
	}
}


void ca_cache_ocsp_store(struct ca_cache *c,
		X509 *cert, X509 *issuer,
		int status, time_t expires)
{
	struct ocsp_entry *e;
	uint8_t name_hash[CA_CACHE_NAME_HASH_LEN];
	uint8_t key_hash[CA_CACHE_KEY_HASH_LEN];
	uint8_t serial[CA_CACHE_SERIAL_MAX];
	int serial_len = 0;

	if(!c || !cert || !issuer) return;
	if(ocsp_key(cert, issuer, name_hash, key_hash, serial,
			CA_CACHE_SERIAL_MAX, &serial_len) != 0){
		return;
	}

	for(e = c->ocsp_head; e; e = e->next){
		if(e->serial_len != serial_len) continue;
		if(memcmp(e->name_hash, name_hash, CA_CACHE_NAME_HASH_LEN) != 0) continue;
		if(memcmp(e->key_hash, key_hash, CA_CACHE_KEY_HASH_LEN) != 0) continue;
		if(memcmp(e->serial, serial, (size_t)serial_len) != 0) continue;
		e->status = status;
		e->expires = expires;
		return;
	}

	while(c->ocsp_count >= CA_CACHE_MAX_OCSP_ENTRIES){
		ocsp_evict_one(c);
	}

	e = mosquitto_calloc(1, sizeof(*e));
	if(!e) return;

	memcpy(e->name_hash, name_hash, CA_CACHE_NAME_HASH_LEN);
	memcpy(e->key_hash, key_hash, CA_CACHE_KEY_HASH_LEN);
	memcpy(e->serial, serial, (size_t)serial_len);
	e->serial_len = serial_len;
	e->status = status;
	e->expires = expires;
	e->next = c->ocsp_head;
	c->ocsp_head = e;
	c->ocsp_count++;
}


/* ---- Blob lookup / store ---------------------------------------------- */

static void blob_evict_one(struct ca_cache *c)
{
	struct blob_entry **cursor, **oldest_link = NULL;
	time_t oldest_exp = 0;
	time_t now = time(NULL);

	cursor = &c->blob_head;
	while(*cursor){
		if((*cursor)->expires != 0 && (*cursor)->expires <= now){
			struct blob_entry *v = *cursor;
			*cursor = v->next;
			mosquitto_free(v->value);
			mosquitto_free(v);
			c->blob_count--;
			return;
		}
		cursor = &(*cursor)->next;
	}

	cursor = &c->blob_head;
	while(*cursor){
		if(oldest_link == NULL || (*cursor)->expires < oldest_exp){
			oldest_link = cursor;
			oldest_exp = (*cursor)->expires;
		}
		cursor = &(*cursor)->next;
	}
	if(oldest_link){
		struct blob_entry *v = *oldest_link;
		*oldest_link = v->next;
		mosquitto_free(v->value);
		mosquitto_free(v);
		c->blob_count--;
	}
}


char *ca_cache_blob_lookup(struct ca_cache *c,
		enum ca_cache_kind kind,
		const unsigned char *key, size_t key_len)
{
	if(!c || !key || key_len == 0 || key_len > CA_CACHE_BLOB_KEY_MAX) return NULL;

	time_t now = time(NULL);
	for(struct blob_entry *e = c->blob_head; e; e = e->next){
		if(e->kind != kind) continue;
		if(e->key_len != key_len) continue;
		if(memcmp(e->key, key, key_len) != 0) continue;
		if(e->expires != 0 && e->expires <= now) return NULL;
		return mosquitto_strdup(e->value);
	}
	return NULL;
}


void ca_cache_blob_store(struct ca_cache *c,
		enum ca_cache_kind kind,
		const unsigned char *key, size_t key_len,
		const char *value_json,
		time_t expires)
{
	struct blob_entry *e;

	if(!c || !key || key_len == 0 || key_len > CA_CACHE_BLOB_KEY_MAX) return;
	if(!value_json) return;

	/* Replace existing entry with same (kind, key). */
	for(e = c->blob_head; e; e = e->next){
		if(e->kind != kind) continue;
		if(e->key_len != key_len) continue;
		if(memcmp(e->key, key, key_len) != 0) continue;
		char *nv = mosquitto_strdup(value_json);
		if(!nv) return;
		mosquitto_free(e->value);
		e->value = nv;
		e->expires = expires;
		return;
	}

	while(c->blob_count >= CA_CACHE_MAX_LDAP_ENTRIES){
		blob_evict_one(c);
	}

	e = mosquitto_calloc(1, sizeof(*e));
	if(!e) return;
	e->value = mosquitto_strdup(value_json);
	if(!e->value){
		mosquitto_free(e);
		return;
	}
	e->kind = kind;
	memcpy(e->key, key, key_len);
	e->key_len = key_len;
	e->expires = expires;
	e->next = c->blob_head;
	c->blob_head = e;
	c->blob_count++;
}
