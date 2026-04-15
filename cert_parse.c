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
 * Identity and AIA extraction helpers for the cert-rego plugin. These are
 * deliberately narrow and allocate return strings with mosquitto_strdup/
 * mosquitto_calloc so they can be freed with mosquitto_free — the plugin
 * never mixes OpenSSL's allocator with mosquitto's.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <mosquitto.h>

#include "cert_auth.h"

#include "audit_log.h" /* for audit_log_escape_json_string — reused as a generic JSON escape */

/* UPN is encoded as an otherName in the SAN with this OID. */
#define UPN_OID "1.3.6.1.4.1.311.20.2.3"


/* Duplicate a counted byte string as a NUL-terminated C string using the
 * mosquitto allocator. Returns NULL on alloc failure or if the input
 * contains an embedded NUL (which would make it unsafe as a username). */
static char *dup_bytes(const unsigned char *buf, int len)
{
	char *out;

	if(len < 0) return NULL;
	for(int i = 0; i < len; i++){
		if(buf[i] == '\0') return NULL;
	}
	out = mosquitto_calloc(1, (size_t)len + 1);
	if(!out) return NULL;
	memcpy(out, buf, (size_t)len);
	return out;
}


static char *extract_cn(X509 *cert)
{
	X509_NAME *subj;
	int idx;
	X509_NAME_ENTRY *entry;
	ASN1_STRING *data;
	unsigned char *utf8 = NULL;
	int len;
	char *result = NULL;

	subj = X509_get_subject_name(cert);
	if(!subj) return NULL;

	idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
	if(idx < 0) return NULL;

	entry = X509_NAME_get_entry(subj, idx);
	if(!entry) return NULL;

	data = X509_NAME_ENTRY_get_data(entry);
	if(!data) return NULL;

	len = ASN1_STRING_to_UTF8(&utf8, data);
	if(len <= 0 || utf8 == NULL) return NULL;

	result = dup_bytes(utf8, len);
	OPENSSL_free(utf8);
	return result;
}


/* extract_cn is used by ca_cert_input_json to populate input.cert.cn as a
 * convenience — other fields (subject_dn, SANs, serial, fingerprint) go
 * into the input doc via their own dedicated emitters below. Policies read
 * the fields they want directly rather than asking the plugin to pre-pick
 * a "primary identity". */


char *ca_cert_ocsp_url(X509 *cert)
{
	STACK_OF(OPENSSL_STRING) *urls;
	char *result = NULL;

	if(!cert) return NULL;

	/* X509_get1_ocsp walks the AIA extension looking for the
	 * id-ad-ocsp access method and returns every URL it finds. We take
	 * the first one — responders typically only list one per cert. */
	urls = X509_get1_ocsp(cert);
	if(!urls) return NULL;

	if(sk_OPENSSL_STRING_num(urls) > 0){
		const char *u = sk_OPENSSL_STRING_value(urls, 0);
		if(u){
			result = mosquitto_strdup(u);
		}
	}

	X509_email_free(urls);
	return result;
}


/* ===========================================================================
 * Full Rego input-document builder for cert.*
 *
 * Builds a JSON object containing every field a policy is plausibly going
 * to care about. The output becomes input.cert in the Rego evaluation.
 * ========================================================================= */

struct json_buf {
	char *data;
	size_t len;
	size_t cap;
};

static bool jb_reserve(struct json_buf *b, size_t extra)
{
	if(b->len + extra + 1 <= b->cap) return true;
	size_t ncap = b->cap ? b->cap * 2 : 512;
	while(ncap < b->len + extra + 1) ncap *= 2;
	char *nd = mosquitto_realloc(b->data, ncap);
	if(!nd) return false;
	b->data = nd;
	b->cap = ncap;
	return true;
}

static bool jb_append(struct json_buf *b, const char *s)
{
	size_t n = strlen(s);
	if(!jb_reserve(b, n)) return false;
	memcpy(b->data + b->len, s, n);
	b->len += n;
	b->data[b->len] = '\0';
	return true;
}

static bool jb_append_jstr(struct json_buf *b, const char *s)
{
	char *esc = audit_log_escape_json_string(s ? s : "");
	if(!esc) return false;
	bool ok = jb_append(b, esc);
	mosquitto_free(esc);
	return ok;
}

static bool jb_append_int64(struct json_buf *b, int64_t v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%lld", (long long)v);
	return jb_append(b, buf);
}


/* Convert an ASN1 time to unix seconds. Returns 0 on failure. */
static int64_t asn1_time_to_unix(const ASN1_TIME *t)
{
	if(!t) return 0;
	struct tm tm;
	if(!ASN1_TIME_to_tm(t, &tm)) return 0;
#ifdef WIN32
	return (int64_t)_mkgmtime(&tm);
#else
	return (int64_t)timegm(&tm);
#endif
}


/* Hex-encode a byte buffer with no separator. buf must hold 2*len+1 bytes. */
static void hex_encode(char *buf, const unsigned char *bytes, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	for(size_t i = 0; i < len; i++){
		buf[2*i]     = hex[(bytes[i] >> 4) & 0xf];
		buf[2*i + 1] = hex[bytes[i] & 0xf];
	}
	buf[2*len] = '\0';
}


static char *cert_fingerprint_sha256_hex(X509 *cert)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	if(!X509_digest(cert, EVP_sha256(), digest, &digest_len)){
		return NULL;
	}
	char *out = mosquitto_malloc((size_t)digest_len * 2 + 1);
	if(!out) return NULL;
	hex_encode(out, digest, digest_len);
	return out;
}


static char *cert_serial_hex(X509 *cert)
{
	const ASN1_INTEGER *sn = X509_get0_serialNumber(cert);
	if(!sn) return mosquitto_strdup("");
	BIGNUM *bn = ASN1_INTEGER_to_BN(sn, NULL);
	if(!bn) return NULL;
	char *bnhex = BN_bn2hex(bn);
	BN_free(bn);
	if(!bnhex) return NULL;
	/* BN_bn2hex uses uppercase; lowercase for consistency with fingerprint. */
	for(char *p = bnhex; *p; p++){
		if(*p >= 'A' && *p <= 'F') *p = (char)(*p + ('a' - 'A'));
	}
	char *out = mosquitto_strdup(bnhex);
	OPENSSL_free(bnhex);
	return out;
}


static bool append_name_as_json_string(struct json_buf *b, X509_NAME *name)
{
	if(!name){
		return jb_append(b, "\"\"");
	}
	BIO *mem = BIO_new(BIO_s_mem());
	if(!mem) return false;
	if(X509_NAME_print_ex(mem, name, 0,
			XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB) <= 0){
		BIO_free(mem);
		return jb_append(b, "\"\"");
	}
	BUF_MEM *bp = NULL;
	BIO_get_mem_ptr(mem, &bp);
	char *tmp = NULL;
	if(bp && bp->length > 0){
		tmp = mosquitto_calloc(1, bp->length + 1);
		if(tmp) memcpy(tmp, bp->data, bp->length);
	}
	BIO_free(mem);
	if(!tmp){
		return jb_append(b, "\"\"");
	}
	bool ok = jb_append_jstr(b, tmp);
	mosquitto_free(tmp);
	return ok;
}


static bool append_san_arrays(struct json_buf *b, X509 *cert)
{
	STACK_OF(GENERAL_NAME) *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

	bool ok = jb_append(b, "\"san\":{\"dns\":[");
	if(!ok){ if(sans) GENERAL_NAMES_free(sans); return false; }

	int n = sans ? sk_GENERAL_NAME_num(sans) : 0;
	bool first;

	/* dns */
	first = true;
	for(int i = 0; i < n; i++){
		const GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
		if(gn->type != GEN_DNS) continue;
		const unsigned char *u = ASN1_STRING_get0_data(gn->d.dNSName);
		int l = ASN1_STRING_length(gn->d.dNSName);
		if(!first){ if(!jb_append(b, ",")) goto fail; }
		first = false;
		char *tmp = mosquitto_calloc(1, (size_t)l + 1);
		if(!tmp) goto fail;
		memcpy(tmp, u, (size_t)l);
		bool g = jb_append_jstr(b, tmp);
		mosquitto_free(tmp);
		if(!g) goto fail;
	}
	if(!jb_append(b, "],\"email\":[")) goto fail;

	/* email */
	first = true;
	for(int i = 0; i < n; i++){
		const GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
		if(gn->type != GEN_EMAIL) continue;
		const unsigned char *u = ASN1_STRING_get0_data(gn->d.rfc822Name);
		int l = ASN1_STRING_length(gn->d.rfc822Name);
		if(!first){ if(!jb_append(b, ",")) goto fail; }
		first = false;
		char *tmp = mosquitto_calloc(1, (size_t)l + 1);
		if(!tmp) goto fail;
		memcpy(tmp, u, (size_t)l);
		bool g = jb_append_jstr(b, tmp);
		mosquitto_free(tmp);
		if(!g) goto fail;
	}
	if(!jb_append(b, "],\"uri\":[")) goto fail;

	/* uri */
	first = true;
	for(int i = 0; i < n; i++){
		const GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
		if(gn->type != GEN_URI) continue;
		const unsigned char *u = ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier);
		int l = ASN1_STRING_length(gn->d.uniformResourceIdentifier);
		if(!first){ if(!jb_append(b, ",")) goto fail; }
		first = false;
		char *tmp = mosquitto_calloc(1, (size_t)l + 1);
		if(!tmp) goto fail;
		memcpy(tmp, u, (size_t)l);
		bool g = jb_append_jstr(b, tmp);
		mosquitto_free(tmp);
		if(!g) goto fail;
	}
	if(!jb_append(b, "]}")) goto fail;

	if(sans) GENERAL_NAMES_free(sans);
	return true;

fail:
	if(sans) GENERAL_NAMES_free(sans);
	return false;
}


/* ===========================================================================
 * AIA (Authority Information Access)
 *
 * Exposes both OCSP and caIssuers URLs found in the AIA extension. Walking
 * AIA by hand (rather than using X509_get1_ocsp) because that helper only
 * returns OCSP URLs — and we want both methods here for:
 *   - policies that want to see caIssuers URLs for logging / audit
 *   - the optional AIA-fetch feature in aia_fetch.c, which uses the
 *     caIssuers URL to download a missing intermediate during chain build
 * ========================================================================= */

/* Write AIA sub-object: {"ocsp_urls":[...], "ca_issuers_urls":[...]}. */
static bool append_aia(struct json_buf *b, X509 *cert)
{
	AUTHORITY_INFO_ACCESS *aia = NULL;
	bool ok = false;

	if(!jb_append(b, "{\"ocsp_urls\":[")) return false;

	aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
	if(!aia){
		return jb_append(b, "],\"ca_issuers_urls\":[]}");
	}

	/* Two passes: first OCSP, then caIssuers. */
	bool first = true;
	for(int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++){
		ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia, i);
		if(!ad) continue;
		if(OBJ_obj2nid(ad->method) != NID_ad_OCSP) continue;
		if(ad->location->type != GEN_URI) continue;
		ASN1_IA5STRING *uri = ad->location->d.uniformResourceIdentifier;

		char *tmp = mosquitto_calloc(1, (size_t)ASN1_STRING_length(uri) + 1);
		if(!tmp) goto out;
		memcpy(tmp, ASN1_STRING_get0_data(uri), (size_t)ASN1_STRING_length(uri));
		if(!first){ if(!jb_append(b, ",")){ mosquitto_free(tmp); goto out; } }
		first = false;
		if(!jb_append_jstr(b, tmp)){ mosquitto_free(tmp); goto out; }
		mosquitto_free(tmp);
	}
	if(!jb_append(b, "],\"ca_issuers_urls\":[")) goto out;

	first = true;
	for(int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++){
		ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia, i);
		if(!ad) continue;
		if(OBJ_obj2nid(ad->method) != NID_ad_ca_issuers) continue;
		if(ad->location->type != GEN_URI) continue;
		ASN1_IA5STRING *uri = ad->location->d.uniformResourceIdentifier;

		char *tmp = mosquitto_calloc(1, (size_t)ASN1_STRING_length(uri) + 1);
		if(!tmp) goto out;
		memcpy(tmp, ASN1_STRING_get0_data(uri), (size_t)ASN1_STRING_length(uri));
		if(!first){ if(!jb_append(b, ",")){ mosquitto_free(tmp); goto out; } }
		first = false;
		if(!jb_append_jstr(b, tmp)){ mosquitto_free(tmp); goto out; }
		mosquitto_free(tmp);
	}
	if(!jb_append(b, "]}")) goto out;
	ok = true;

out:
	AUTHORITY_INFO_ACCESS_free(aia);
	return ok;
}


/* Walk the crlDistributionPoints extension and collect every URI-type
 * distribution point. Returns a NULL-terminated array of mosquitto_
 * strdup'd strings (caller frees each + the array) or NULL if the ext
 * is missing / contains no URIs. */
char **ca_cert_crl_dp_urls(X509 *cert, size_t *count_out)
{
	if(count_out) *count_out = 0;
	if(!cert) return NULL;

	CRL_DIST_POINTS *dps = X509_get_ext_d2i(cert,
			NID_crl_distribution_points, NULL, NULL);
	if(!dps) return NULL;

	/* First pass: count. */
	size_t n = 0;
	for(int i = 0; i < sk_DIST_POINT_num(dps); i++){
		DIST_POINT *dp = sk_DIST_POINT_value(dps, i);
		if(!dp || !dp->distpoint) continue;
		if(dp->distpoint->type != 0) continue;   /* fullname only */
		GENERAL_NAMES *names = dp->distpoint->name.fullname;
		for(int j = 0; j < sk_GENERAL_NAME_num(names); j++){
			GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, j);
			if(gn && gn->type == GEN_URI) n++;
		}
	}
	if(n == 0){
		CRL_DIST_POINTS_free(dps);
		return NULL;
	}

	char **out = mosquitto_calloc(n + 1, sizeof(char *));
	if(!out){
		CRL_DIST_POINTS_free(dps);
		return NULL;
	}

	/* Second pass: populate. */
	size_t w = 0;
	for(int i = 0; i < sk_DIST_POINT_num(dps); i++){
		DIST_POINT *dp = sk_DIST_POINT_value(dps, i);
		if(!dp || !dp->distpoint) continue;
		if(dp->distpoint->type != 0) continue;
		GENERAL_NAMES *names = dp->distpoint->name.fullname;
		for(int j = 0; j < sk_GENERAL_NAME_num(names); j++){
			GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, j);
			if(!gn || gn->type != GEN_URI) continue;
			ASN1_IA5STRING *uri = gn->d.uniformResourceIdentifier;
			char *s = mosquitto_calloc(1, (size_t)ASN1_STRING_length(uri) + 1);
			if(!s) goto oom;
			memcpy(s, ASN1_STRING_get0_data(uri),
					(size_t)ASN1_STRING_length(uri));
			out[w++] = s;
		}
	}
	out[w] = NULL;
	if(count_out) *count_out = w;
	CRL_DIST_POINTS_free(dps);
	return out;

oom:
	for(size_t i = 0; i < w; i++) mosquitto_free(out[i]);
	mosquitto_free(out);
	CRL_DIST_POINTS_free(dps);
	return NULL;
}


/* Public helper for aia_fetch.c: return the first caIssuers URL on cert,
 * mosquitto_strdup'd. NULL if absent. */
char *ca_cert_ca_issuers_url(X509 *cert)
{
	AUTHORITY_INFO_ACCESS *aia = NULL;
	char *out = NULL;

	if(!cert) return NULL;
	aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
	if(!aia) return NULL;

	for(int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++){
		ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia, i);
		if(!ad) continue;
		if(OBJ_obj2nid(ad->method) != NID_ad_ca_issuers) continue;
		if(ad->location->type != GEN_URI) continue;
		ASN1_IA5STRING *uri = ad->location->d.uniformResourceIdentifier;

		out = mosquitto_calloc(1, (size_t)ASN1_STRING_length(uri) + 1);
		if(!out) break;
		memcpy(out, ASN1_STRING_get0_data(uri),
				(size_t)ASN1_STRING_length(uri));
		break;
	}

	AUTHORITY_INFO_ACCESS_free(aia);
	return out;
}


/* ===========================================================================
 * Custom OID extensions — wide parsing
 *
 * For every X509 extension whose OID is unknown to OpenSSL (NID_undef),
 * we emit an entry describing the raw content with the best guess at its
 * ASN.1 type. The goal is to let policies match custom certificate
 * extensions by OID string ("1.3.6.1.4.1.99999.1") and read their values
 * without the plugin having to know the full vendor schema.
 *
 * Strategy:
 *   1. Pull the extension's octet-string payload via X509_EXTENSION_get_data.
 *   2. Try to d2i-decode it as successive ASN.1 string types. If any
 *      succeeds and the result is a printable string, emit it as `value`
 *      with `value_type` set to the matched type.
 *   3. If all fail, emit `value_hex` with the raw DER bytes.
 *
 * The dotted OID and critical flag are always emitted.
 * ========================================================================= */

static bool jb_append_hex(struct json_buf *b, const unsigned char *buf, size_t len)
{
	if(!jb_append(b, "\"")) return false;
	static const char hex[] = "0123456789abcdef";
	char pair[3] = {0};
	for(size_t i = 0; i < len; i++){
		pair[0] = hex[(buf[i] >> 4) & 0xf];
		pair[1] = hex[buf[i] & 0xf];
		if(!jb_append(b, pair)) return false;
	}
	return jb_append(b, "\"");
}


/* Parse a DER TLV header at `in[0..inlen]`. On success, returns the length
 * of the header in bytes and sets *tag_out / *content_out / *content_len.
 * On malformed input returns 0. Handles BER short-form and long-form
 * lengths up to 4 content-length bytes (16 MB) — plenty for cert
 * extensions. */
static int parse_tlv_header(const unsigned char *in, int inlen,
		int *tag_out,
		const unsigned char **content_out,
		int *content_len_out)
{
	if(inlen < 2) return 0;

	int tag = in[0] & 0x1f;          /* primitive tags only */
	if((in[0] & 0x1f) == 0x1f) return 0;  /* multi-byte tag unsupported */

	int hdr = 2;
	int len = in[1];
	if(len & 0x80){
		int nbytes = len & 0x7f;
		if(nbytes == 0 || nbytes > 4) return 0;
		if(inlen < 2 + nbytes) return 0;
		len = 0;
		for(int i = 0; i < nbytes; i++){
			len = (len << 8) | in[2 + i];
		}
		hdr = 2 + nbytes;
	}
	if(len < 0 || hdr + len > inlen) return 0;

	*tag_out = tag;
	*content_out = in + hdr;
	*content_len_out = len;
	return hdr;
}


/* ASN.1 primitive-string tag values (class=UNIVERSAL, primitive=P). We
 * match against the low 5 bits of the tag byte. */
#define ASN1_TAG_UTF8STRING       0x0c
#define ASN1_TAG_PRINTABLESTRING  0x13
#define ASN1_TAG_IA5STRING        0x16
#define ASN1_TAG_VISIBLESTRING    0x1a
#define ASN1_TAG_BMPSTRING        0x1e
#define ASN1_TAG_T61STRING        0x14
#define ASN1_TAG_UNIVERSALSTRING  0x1c
#define ASN1_TAG_OCTETSTRING      0x04


static bool bytes_all_printable(const unsigned char *buf, int len)
{
	if(len <= 0) return false;
	for(int i = 0; i < len; i++){
		unsigned char c = buf[i];
		if(c == '\t' || c == '\n' || c == '\r') continue;
		if(c < 0x20 || c == 0x7f) return false;
	}
	return true;
}


/* Convert BMPString (UCS-2 big-endian) to UTF-8 via a tiny inline
 * converter. Skip non-BMP plane handling — cert extensions never use
 * that in practice. */
static char *bmp_to_utf8(const unsigned char *in, int inlen)
{
	if(inlen < 0 || (inlen % 2) != 0) return NULL;
	/* Worst case UTF-8 expansion of BMP: 3 bytes per code point. */
	size_t cap = (size_t)(inlen / 2) * 3 + 1;
	char *out = mosquitto_malloc(cap);
	if(!out) return NULL;
	size_t w = 0;
	for(int i = 0; i < inlen; i += 2){
		unsigned int cp = ((unsigned)in[i] << 8) | in[i+1];
		if(cp < 0x80){
			out[w++] = (char)cp;
		}else if(cp < 0x800){
			out[w++] = (char)(0xc0 | (cp >> 6));
			out[w++] = (char)(0x80 | (cp & 0x3f));
		}else{
			out[w++] = (char)(0xe0 | (cp >> 12));
			out[w++] = (char)(0x80 | ((cp >> 6) & 0x3f));
			out[w++] = (char)(0x80 | (cp & 0x3f));
		}
	}
	out[w] = '\0';
	return out;
}


/* Attempt to decode `in` (length `inlen`) and surface a printable UTF-8
 * string. On success returns a mosquitto_strdup'd string and sets
 * *type_out to the ASN.1 type label. Returns NULL on failure.
 *
 * Order of attempts (widest first):
 *   UTF8String, PrintableString, IA5String, VisibleString, T61String,
 *   UniversalString, BMPString, OCTET STRING (unwrap + recurse).
 * Final fallback treats the whole blob as plain bytes and, if every byte
 * is printable ASCII, emits it — catches custom extensions in the wild
 * that carry a bare string with no ASN.1 wrapper.
 */
static char *decode_as_string(const unsigned char *in, int inlen,
		const char **type_out)
{
	if(inlen <= 0){
		if(type_out) *type_out = "opaque";
		return NULL;
	}

	int tag = 0, content_len = 0;
	const unsigned char *content = NULL;
	int hdr = parse_tlv_header(in, inlen, &tag, &content, &content_len);

	/* Whole-buffer must be exactly one TLV for these string cases, i.e.
	 * header + content equals the input length. Looser inputs fall
	 * through to the printable-ASCII fallback. */
	if(hdr > 0 && hdr + content_len == inlen){
		switch(tag){
			case ASN1_TAG_UTF8STRING:
				if(type_out) *type_out = "utf8string";
				return dup_bytes(content, content_len);
			case ASN1_TAG_PRINTABLESTRING:
				if(type_out) *type_out = "printablestring";
				return dup_bytes(content, content_len);
			case ASN1_TAG_IA5STRING:
				if(type_out) *type_out = "ia5string";
				return dup_bytes(content, content_len);
			case ASN1_TAG_VISIBLESTRING:
				if(type_out) *type_out = "visiblestring";
				return dup_bytes(content, content_len);
			case ASN1_TAG_T61STRING:
				/* T61 is a 7-bit superset of ASCII for the common subset;
				 * accept if printable. Full T61 decoding isn't worth it. */
				if(bytes_all_printable(content, content_len)){
					if(type_out) *type_out = "t61string";
					return dup_bytes(content, content_len);
				}
				break;
			case ASN1_TAG_BMPSTRING:
				if(type_out) *type_out = "bmpstring";
				return bmp_to_utf8(content, content_len);
			case ASN1_TAG_UNIVERSALSTRING:
				/* UCS-4 big-endian. Uncommon in practice; decode only the
				 * BMP subset (first two bytes zero). */
				if((content_len % 4) == 0){
					unsigned char *bmp = mosquitto_malloc((size_t)(content_len / 2));
					if(!bmp) return NULL;
					for(int i = 0; i < content_len; i += 4){
						bmp[i / 2]     = content[i + 2];
						bmp[i / 2 + 1] = content[i + 3];
					}
					char *r = bmp_to_utf8(bmp, content_len / 2);
					mosquitto_free(bmp);
					if(r){
						if(type_out) *type_out = "universalstring";
						return r;
					}
				}
				break;
			case ASN1_TAG_OCTETSTRING:
				{
					const char *inner_type = NULL;
					char *inner = decode_as_string(content, content_len, &inner_type);
					if(inner){
						if(type_out) *type_out = inner_type ? inner_type : "octet_string";
						return inner;
					}
				}
				break;
		}
	}

	/* Printable-ASCII heuristic for badly tagged custom extensions. */
	if(bytes_all_printable(in, inlen)){
		char *r = dup_bytes(in, inlen);
		if(r){
			if(type_out) *type_out = "raw_ascii";
			return r;
		}
	}

	if(type_out) *type_out = "opaque";
	return NULL;
}


/* Emit custom_extensions array: every extension on the cert whose OID is
 * unknown to OpenSSL. We skip known NIDs to avoid duplicating fields we
 * already expose (SAN, AIA, basicConstraints, etc.). */
static bool append_custom_extensions(struct json_buf *b, X509 *cert)
{
	if(!jb_append(b, "[")) return false;

	int n = X509_get_ext_count(cert);
	bool first = true;
	char oid_buf[128];

	for(int i = 0; i < n; i++){
		X509_EXTENSION *ext = X509_get_ext(cert, i);
		if(!ext) continue;

		ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
		if(!obj) continue;

		int nid = OBJ_obj2nid(obj);
		if(nid != NID_undef){
			/* Known NID — skip; either we already emit it elsewhere
			 * (SAN, AIA, basicConstraints, keyUsage, etc.) or it's a
			 * boring standard extension that adds no signal. */
			continue;
		}

		/* Dotted OID string. OBJ_obj2txt returns length needed; a 128-byte
		 * buffer is ample for any real-world OID. */
		int oid_len = OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
		if(oid_len <= 0 || (size_t)oid_len >= sizeof(oid_buf)) continue;

		ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ext);
		if(!data) continue;

		const unsigned char *raw = ASN1_STRING_get0_data(data);
		int raw_len = ASN1_STRING_length(data);

		const char *value_type = "opaque";
		char *decoded = decode_as_string(raw, raw_len, &value_type);

		if(!first){
			if(!jb_append(b, ",")){ mosquitto_free(decoded); goto fail; }
		}
		first = false;

		if(!jb_append(b, "{\"oid\":")){ mosquitto_free(decoded); goto fail; }
		if(!jb_append_jstr(b, oid_buf)){ mosquitto_free(decoded); goto fail; }

		if(!jb_append(b, ",\"critical\":")){ mosquitto_free(decoded); goto fail; }
		if(!jb_append(b, X509_EXTENSION_get_critical(ext) ? "true" : "false")){
			mosquitto_free(decoded); goto fail;
		}

		if(!jb_append(b, ",\"value_type\":")){ mosquitto_free(decoded); goto fail; }
		if(!jb_append_jstr(b, value_type)){ mosquitto_free(decoded); goto fail; }

		if(decoded){
			if(!jb_append(b, ",\"value\":")){ mosquitto_free(decoded); goto fail; }
			if(!jb_append_jstr(b, decoded)){ mosquitto_free(decoded); goto fail; }
		}else{
			if(!jb_append(b, ",\"value\":null")){ goto fail; }
		}
		mosquitto_free(decoded);

		if(!jb_append(b, ",\"value_hex\":")) goto fail;
		if(!jb_append_hex(b, raw, (size_t)raw_len)) goto fail;

		if(!jb_append(b, "}")) goto fail;
	}

	return jb_append(b, "]");

fail:
	return false;
}


/* Emit a trust_anchor sub-object (without the leading key or comma) for the
 * given anchor cert. If anchor is NULL, emits the JSON literal `null`. */
static bool append_trust_anchor(struct json_buf *b, X509 *anchor)
{
	if(!anchor){
		return jb_append(b, "null");
	}
	if(!jb_append(b, "{\"subject_dn\":")) return false;
	if(!append_name_as_json_string(b, X509_get_subject_name(anchor))) return false;

	char *fp = cert_fingerprint_sha256_hex(anchor);
	if(!jb_append(b, ",\"fingerprint_sha256\":")) { mosquitto_free(fp); return false; }
	bool ok = jb_append_jstr(b, fp ? fp : "");
	mosquitto_free(fp);
	if(!ok) return false;

	return jb_append(b, "}");
}


/* Emit the "verify_ok" + "errors" portion of a chain entry. Errors are
 * surfaced as objects with code + message so policies can pattern-match
 * on the short code or render the message in audit output. */
static bool append_chain_entry_verify(struct json_buf *b,
		const struct ca_verify_cert_result *vr)
{
	if(!jb_append(b, ",\"verify_ok\":")) return false;
	if(!jb_append(b, vr->verify_ok ? "true" : "false")) return false;

	if(!jb_append(b, ",\"errors\":[")) return false;
	for(int i = 0; i < vr->error_count; i++){
		if(i > 0){ if(!jb_append(b, ",")) return false; }
		if(!jb_append(b, "{\"code\":")) return false;
		if(!jb_append_jstr(b, vr->short_codes[i] ? vr->short_codes[i] : "other")) return false;
		if(!jb_append(b, ",\"message\":")) return false;
		if(!jb_append_jstr(b, vr->messages[i] ? vr->messages[i] : "")) return false;
		if(!jb_append(b, "}")) return false;
	}
	return jb_append(b, "]");
}


/* Emit one chain-entry object, including the per-cert verification result
 * if `state` has one at this depth. Policies inspect `verify_ok` +
 * `errors[]` to make override decisions (e.g. accept an expired
 * intermediate under specific conditions). */
static bool append_chain_entry(struct json_buf *b, X509 *cert, int depth,
		const struct ca_verify_state *state)
{
	char depth_buf[64];
	snprintf(depth_buf, sizeof(depth_buf), "{\"depth\":%d,\"subject_dn\":", depth);
	if(!jb_append(b, depth_buf)) return false;
	if(!append_name_as_json_string(b, X509_get_subject_name(cert))) return false;

	if(!jb_append(b, ",\"issuer_dn\":")) return false;
	if(!append_name_as_json_string(b, X509_get_issuer_name(cert))) return false;

	char *serial = cert_serial_hex(cert);
	if(!jb_append(b, ",\"serial\":")) { mosquitto_free(serial); return false; }
	bool ok = jb_append_jstr(b, serial ? serial : "");
	mosquitto_free(serial);
	if(!ok) return false;

	char *fp = cert_fingerprint_sha256_hex(cert);
	if(!jb_append(b, ",\"fingerprint_sha256\":")) { mosquitto_free(fp); return false; }
	ok = jb_append_jstr(b, fp ? fp : "");
	mosquitto_free(fp);
	if(!ok) return false;

	if(!jb_append(b, ",\"not_before_unix\":")) return false;
	if(!jb_append_int64(b, asn1_time_to_unix(X509_get0_notBefore(cert)))) return false;
	if(!jb_append(b, ",\"not_after_unix\":")) return false;
	if(!jb_append_int64(b, asn1_time_to_unix(X509_get0_notAfter(cert)))) return false;

	/* Per-cert verification outcome. If state was supplied and this
	 * depth has a record, emit it; otherwise mark verify_ok=true with
	 * an empty errors array (nothing to report). */
	if(state && depth >= 0 && depth < state->cert_count){
		if(!append_chain_entry_verify(b, &state->per_cert[depth])) return false;
	}else{
		if(!jb_append(b, ",\"verify_ok\":true,\"errors\":[]")) return false;
	}

	return jb_append(b, "}");
}


char *ca_cert_input_json(X509 *leaf,
		STACK_OF(X509) *chain,
		const struct ca_verify_state *state)
{
	if(!leaf) return NULL;

	struct json_buf b = {0};
	char *cn = NULL;
	char *fp = NULL;
	char *serial = NULL;

	/* Anchor is the last element of the chain — but we only present it
	 * as input.cert.trust_anchor if chain verification actually succeeded.
	 * Policies that want the "structural anchor" regardless can still
	 * read input.cert.chain[last].subject_dn. */
	X509 *anchor = NULL;
	int chain_n = 0;
	if(chain){
		chain_n = sk_X509_num(chain);
		if(chain_n > 0 && state && state->chain_ok){
			anchor = sk_X509_value(chain, chain_n - 1);
		}
	}

	if(!jb_append(&b, "{")) goto oom;

	/* subject_dn */
	if(!jb_append(&b, "\"subject_dn\":")) goto oom;
	if(!append_name_as_json_string(&b, X509_get_subject_name(leaf))) goto oom;

	/* cn */
	cn = extract_cn(leaf);
	if(!jb_append(&b, ",\"cn\":")) goto oom;
	if(!jb_append_jstr(&b, cn ? cn : "")) goto oom;

	/* issuer_dn (direct parent in the chain, not the root) */
	if(!jb_append(&b, ",\"issuer_dn\":")) goto oom;
	if(!append_name_as_json_string(&b, X509_get_issuer_name(leaf))) goto oom;

	/* serial */
	serial = cert_serial_hex(leaf);
	if(!jb_append(&b, ",\"serial\":")) goto oom;
	if(!jb_append_jstr(&b, serial ? serial : "")) goto oom;

	/* not_before / not_after — unix seconds */
	if(!jb_append(&b, ",\"not_before_unix\":")) goto oom;
	if(!jb_append_int64(&b, asn1_time_to_unix(X509_get0_notBefore(leaf)))) goto oom;
	if(!jb_append(&b, ",\"not_after_unix\":")) goto oom;
	if(!jb_append_int64(&b, asn1_time_to_unix(X509_get0_notAfter(leaf)))) goto oom;

	/* fingerprint_sha256 */
	fp = cert_fingerprint_sha256_hex(leaf);
	if(!jb_append(&b, ",\"fingerprint_sha256\":")) goto oom;
	if(!jb_append_jstr(&b, fp ? fp : "")) goto oom;

	/* san */
	if(!jb_append(&b, ",")) goto oom;
	if(!append_san_arrays(&b, leaf)) goto oom;

	/* aia — both OCSP and caIssuers URLs. Policies may use these for
	 * logging / audit or to drive the ocsp.check() flow. */
	if(!jb_append(&b, ",\"aia\":")) goto oom;
	if(!append_aia(&b, leaf)) goto oom;

	/* crl_urls — HTTP(S) distribution points from crlDistributionPoints.
	 * Policies use these for logging; actual CRL lookup happens via the
	 * crl.check() host function, which consults the same URLs. */
	{
		size_t nurls = 0;
		char **urls = ca_cert_crl_dp_urls(leaf, &nurls);
		if(!jb_append(&b, ",\"crl_urls\":[")) {
			if(urls){ for(size_t k = 0; k < nurls; k++) mosquitto_free(urls[k]);
				mosquitto_free(urls); }
			goto oom;
		}
		for(size_t k = 0; k < nurls; k++){
			if(k > 0){ if(!jb_append(&b, ",")) {
				for(size_t j = 0; j < nurls; j++) mosquitto_free(urls[j]);
				mosquitto_free(urls);
				goto oom;
			} }
			if(!jb_append_jstr(&b, urls[k])) {
				for(size_t j = 0; j < nurls; j++) mosquitto_free(urls[j]);
				mosquitto_free(urls);
				goto oom;
			}
		}
		if(!jb_append(&b, "]")) {
			if(urls){ for(size_t k = 0; k < nurls; k++) mosquitto_free(urls[k]);
				mosquitto_free(urls); }
			goto oom;
		}
		if(urls){ for(size_t k = 0; k < nurls; k++) mosquitto_free(urls[k]);
			mosquitto_free(urls); }
	}

	/* custom_extensions — every X509 extension with an OID OpenSSL
	 * doesn't know, decoded as widely as possible. Policies match by
	 * OID dotted string. */
	if(!jb_append(&b, ",\"custom_extensions\":")) goto oom;
	if(!append_custom_extensions(&b, leaf)) goto oom;

	/* trust_anchor — only populated when chain verification succeeded.
	 * On a broken chain the policy inspects input.cert.chain[].verify_ok
	 * and decides whether to override. */
	if(!jb_append(&b, ",\"trust_anchor\":")) goto oom;
	if(!append_trust_anchor(&b, anchor)) goto oom;

	/* chain_ok — summary bool. A policy that doesn't want to care about
	 * per-cert overrides can just gate on this. */
	if(!jb_append(&b, ",\"chain_ok\":")) goto oom;
	if(!jb_append(&b, (state && state->chain_ok) ? "true" : "false")) goto oom;

	/* chain_errors — deduplicated short codes across the whole chain.
	 * Empty array when chain_ok is true. */
	if(!jb_append(&b, ",\"chain_errors\":[")) goto oom;
	if(state){
		for(int i = 0; i < state->distinct_count; i++){
			if(i > 0){ if(!jb_append(&b, ",")) goto oom; }
			if(!jb_append_jstr(&b, state->distinct_codes[i] ?
					state->distinct_codes[i] : "other")) goto oom;
		}
	}
	if(!jb_append(&b, "]")) goto oom;

	/* chain — full chain leaf→root (or partial if verification failed
	 * partway through), with per-cert verify_ok + errors embedded.
	 * Policies that want override control iterate this array.
	 *
	 * Special case: if the chain is empty (total verification failure
	 * with no partial result), emit a leaf-only entry so policies can
	 * still reason about the cert they were presented. */
	if(!jb_append(&b, ",\"chain\":[")) goto oom;
	if(chain_n > 0){
		for(int i = 0; i < chain_n; i++){
			X509 *c = sk_X509_value(chain, i);
			if(!c) continue;
			if(i > 0){
				if(!jb_append(&b, ",")) goto oom;
			}
			if(!append_chain_entry(&b, c, i, state)) goto oom;
		}
	}else{
		/* Leaf-only view with the verification state (if any) attached
		 * at depth 0. */
		if(!append_chain_entry(&b, leaf, 0, state)) goto oom;
	}
	if(!jb_append(&b, "]")) goto oom;

	if(!jb_append(&b, "}")) goto oom;

	mosquitto_free(cn);
	mosquitto_free(fp);
	mosquitto_free(serial);
	return b.data;

oom:
	mosquitto_free(cn);
	mosquitto_free(fp);
	mosquitto_free(serial);
	mosquitto_free(b.data);
	return NULL;
}


/* ===========================================================================
 * Audit-extras builders. Produce JSON object bodies (no surrounding braces)
 * for audit_log_event_at(extras_json=...). All strings truncated.
 * ========================================================================= */

/* Truncating variant of jb_append_jstr — caps at AUDIT_DN_MAX_CHARS chars. */
static bool jb_append_jstr_trunc(struct json_buf *b, const char *s)
{
	char *esc = audit_log_escape_json_string_truncated(s ? s : "",
			AUDIT_DN_MAX_CHARS);
	if(!esc) return false;
	bool ok = jb_append(b, esc);
	mosquitto_free(esc);
	return ok;
}


/* Same as append_name_as_json_string but truncates the rendered DN. */
static bool jb_append_name_trunc(struct json_buf *b, X509_NAME *name)
{
	if(!name) return jb_append(b, "\"\"");
	BIO *mem = BIO_new(BIO_s_mem());
	if(!mem) return false;
	if(X509_NAME_print_ex(mem, name, 0,
			XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB) <= 0){
		BIO_free(mem);
		return jb_append(b, "\"\"");
	}
	BUF_MEM *bp = NULL;
	BIO_get_mem_ptr(mem, &bp);
	char *tmp = NULL;
	if(bp && bp->length > 0){
		tmp = mosquitto_calloc(1, bp->length + 1);
		if(tmp) memcpy(tmp, bp->data, bp->length);
	}
	BIO_free(mem);
	if(!tmp){
		return jb_append(b, "\"\"");
	}
	bool ok = jb_append_jstr_trunc(b, tmp);
	mosquitto_free(tmp);
	return ok;
}


char *ca_cert_audit_core_extras(X509 *leaf,
		STACK_OF(X509) *chain,
		const struct ca_verify_state *state)
{
	if(!leaf) return NULL;

	struct json_buf b = {0};
	char *cn = NULL;
	char *fp = NULL;
	char *serial = NULL;
	char *anchor_fp = NULL;

	cn = extract_cn(leaf);
	if(!jb_append(&b, "\"cn\":")) goto oom;
	if(!jb_append_jstr_trunc(&b, cn ? cn : "")) goto oom;

	if(!jb_append(&b, ",\"subject_dn\":")) goto oom;
	if(!jb_append_name_trunc(&b, X509_get_subject_name(leaf))) goto oom;

	if(!jb_append(&b, ",\"issuer_dn\":")) goto oom;
	if(!jb_append_name_trunc(&b, X509_get_issuer_name(leaf))) goto oom;

	serial = cert_serial_hex(leaf);
	if(!jb_append(&b, ",\"serial\":")) goto oom;
	if(!jb_append_jstr(&b, serial ? serial : "")) goto oom;

	fp = cert_fingerprint_sha256_hex(leaf);
	if(!jb_append(&b, ",\"fingerprint_sha256\":")) goto oom;
	if(!jb_append_jstr(&b, fp ? fp : "")) goto oom;

	if(!jb_append(&b, ",\"trust_anchor_fp\":")) goto oom;
	int chain_n = chain ? sk_X509_num(chain) : 0;
	if(state && state->chain_ok && chain_n > 0){
		anchor_fp = cert_fingerprint_sha256_hex(sk_X509_value(chain, chain_n - 1));
		if(!jb_append_jstr(&b, anchor_fp ? anchor_fp : "")) goto oom;
	}else{
		if(!jb_append(&b, "null")) goto oom;
	}

	if(!jb_append(&b, ",\"chain_ok\":")) goto oom;
	if(!jb_append(&b, (state && state->chain_ok) ? "true" : "false")) goto oom;

	if(!jb_append(&b, ",\"chain_errors\":[")) goto oom;
	if(state){
		for(int i = 0; i < state->distinct_count; i++){
			if(i > 0){ if(!jb_append(&b, ",")) goto oom; }
			if(!jb_append_jstr(&b, state->distinct_codes[i] ?
					state->distinct_codes[i] : "other")) goto oom;
		}
	}
	if(!jb_append(&b, "]")) goto oom;

	mosquitto_free(cn);
	mosquitto_free(fp);
	mosquitto_free(serial);
	mosquitto_free(anchor_fp);
	return b.data;

oom:
	mosquitto_free(cn);
	mosquitto_free(fp);
	mosquitto_free(serial);
	mosquitto_free(anchor_fp);
	mosquitto_free(b.data);
	return NULL;
}


/* Per-cert chain entry for audit. Smaller than the policy-input entry —
 * errors[] are emitted as bare short codes (no message), DNs truncated. */
static bool append_audit_chain_entry(struct json_buf *b, X509 *cert, int depth,
		const struct ca_verify_state *state)
{
	char depth_buf[64];
	snprintf(depth_buf, sizeof(depth_buf), "{\"depth\":%d,\"subject_dn\":", depth);
	if(!jb_append(b, depth_buf)) return false;
	if(!jb_append_name_trunc(b, X509_get_subject_name(cert))) return false;

	if(!jb_append(b, ",\"issuer_dn\":")) return false;
	if(!jb_append_name_trunc(b, X509_get_issuer_name(cert))) return false;

	char *serial = cert_serial_hex(cert);
	if(!jb_append(b, ",\"serial\":")) { mosquitto_free(serial); return false; }
	bool ok = jb_append_jstr(b, serial ? serial : "");
	mosquitto_free(serial);
	if(!ok) return false;

	char *fp = cert_fingerprint_sha256_hex(cert);
	if(!jb_append(b, ",\"fingerprint_sha256\":")) { mosquitto_free(fp); return false; }
	ok = jb_append_jstr(b, fp ? fp : "");
	mosquitto_free(fp);
	if(!ok) return false;

	if(!jb_append(b, ",\"not_before_unix\":")) return false;
	if(!jb_append_int64(b, asn1_time_to_unix(X509_get0_notBefore(cert)))) return false;
	if(!jb_append(b, ",\"not_after_unix\":")) return false;
	if(!jb_append_int64(b, asn1_time_to_unix(X509_get0_notAfter(cert)))) return false;

	bool verify_ok = true;
	const struct ca_verify_cert_result *vr = NULL;
	if(state && depth >= 0 && depth < state->cert_count){
		vr = &state->per_cert[depth];
		verify_ok = vr->verify_ok;
	}
	if(!jb_append(b, ",\"verify_ok\":")) return false;
	if(!jb_append(b, verify_ok ? "true" : "false")) return false;

	if(!jb_append(b, ",\"errors\":[")) return false;
	if(vr){
		for(int i = 0; i < vr->error_count; i++){
			if(i > 0){ if(!jb_append(b, ",")) return false; }
			if(!jb_append_jstr(b, vr->short_codes[i] ?
					vr->short_codes[i] : "other")) return false;
		}
	}
	if(!jb_append(b, "]")) return false;

	return jb_append(b, "}");
}


char *ca_cert_audit_chain_extras(STACK_OF(X509) *chain,
		const struct ca_verify_state *state,
		int max_depth)
{
	if(max_depth <= 0) max_depth = 8;

	struct json_buf b = {0};
	if(!jb_append(&b, "\"chain\":[")) goto oom;

	int total = chain ? sk_X509_num(chain) : 0;
	int emit = total < max_depth ? total : max_depth;

	for(int i = 0; i < emit; i++){
		X509 *c = sk_X509_value(chain, i);
		if(!c) continue;
		if(i > 0){ if(!jb_append(&b, ",")) goto oom; }
		if(!append_audit_chain_entry(&b, c, i, state)) goto oom;
	}
	if(!jb_append(&b, "]")) goto oom;

	if(total > emit){
		if(!jb_append(&b, ",\"chain_truncated\":true")) goto oom;
	}
	return b.data;

oom:
	mosquitto_free(b.data);
	return NULL;
}


char *ca_cert_audit_san_extras(X509 *leaf)
{
	if(!leaf) return NULL;
	struct json_buf b = {0};
	if(!append_san_arrays(&b, leaf)) goto oom;
	return b.data;
oom:
	mosquitto_free(b.data);
	return NULL;
}


char *ca_cert_audit_custom_oid_extras(X509 *leaf)
{
	if(!leaf) return NULL;
	struct json_buf b = {0};
	if(!jb_append(&b, "\"custom_extensions\":")) goto oom;
	if(!append_custom_extensions(&b, leaf)) goto oom;
	return b.data;
oom:
	mosquitto_free(b.data);
	return NULL;
}
