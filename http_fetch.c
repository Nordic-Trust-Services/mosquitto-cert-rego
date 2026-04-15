/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <mosquitto.h>

#include "http_fetch.h"


const char *http_fetch_rc_str(enum http_fetch_rc rc)
{
	switch(rc){
		case HTTP_FETCH_OK:              return "ok";
		case HTTP_FETCH_BAD_URL:         return "bad_url";
		case HTTP_FETCH_CONNECT_FAILED:  return "connect_failed";
		case HTTP_FETCH_WRITE_FAILED:    return "write_failed";
		case HTTP_FETCH_READ_FAILED:     return "read_failed";
		case HTTP_FETCH_TOO_LARGE:       return "too_large";
		case HTTP_FETCH_BAD_RESPONSE:    return "bad_response";
		case HTTP_FETCH_OOM:             return "oom";
	}
	return "unknown";
}


struct parsed_url {
	bool tls;
	char *host;
	char *port;
	char *path;
};


static void parsed_url_free(struct parsed_url *u)
{
	if(!u) return;
	mosquitto_free(u->host);
	mosquitto_free(u->port);
	mosquitto_free(u->path);
	u->host = u->port = u->path = NULL;
}


static bool parse_http_url(const char *url, struct parsed_url *out)
{
	memset(out, 0, sizeof(*out));

	if(!strncasecmp(url, "http://", 7)){
		out->tls = false;
		url += 7;
		out->port = mosquitto_strdup("80");
	}else if(!strncasecmp(url, "https://", 8)){
		out->tls = true;
		url += 8;
		out->port = mosquitto_strdup("443");
	}else{
		return false;
	}
	if(!out->port) return false;

	const char *slash = strchr(url, '/');
	const char *host_end = slash ? slash : url + strlen(url);
	const char *colon = NULL;
	for(const char *p = url; p < host_end; p++){
		if(*p == ':'){ colon = p; break; }
	}
	const char *host_stop = colon ? colon : host_end;
	size_t host_len = (size_t)(host_stop - url);
	if(host_len == 0){
		parsed_url_free(out);
		return false;
	}
	out->host = mosquitto_calloc(1, host_len + 1);
	if(!out->host){ parsed_url_free(out); return false; }
	memcpy(out->host, url, host_len);

	if(colon){
		size_t port_len = (size_t)(host_end - colon - 1);
		if(port_len == 0 || port_len > 7){ parsed_url_free(out); return false; }
		mosquitto_free(out->port);
		out->port = mosquitto_calloc(1, port_len + 1);
		if(!out->port){ parsed_url_free(out); return false; }
		memcpy(out->port, colon + 1, port_len);
	}

	if(slash){
		out->path = mosquitto_strdup(slash);
	}else{
		out->path = mosquitto_strdup("/");
	}
	if(!out->path){ parsed_url_free(out); return false; }
	return true;
}


static BIO *open_bio(const struct parsed_url *u, long timeout_ms, SSL_CTX **ctx_out)
{
	*ctx_out = NULL;
	char host_port[512];
	snprintf(host_port, sizeof(host_port), "%s:%s", u->host, u->port);
	(void)timeout_ms;

	if(u->tls){
		SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
		if(!ctx) return NULL;
		SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
		if(!SSL_CTX_set_default_verify_paths(ctx)){
			SSL_CTX_free(ctx);
			return NULL;
		}
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		BIO *bio = BIO_new_ssl_connect(ctx);
		if(!bio){ SSL_CTX_free(ctx); return NULL; }
		BIO_set_conn_hostname(bio, host_port);

		SSL *ssl = NULL;
		BIO_get_ssl(bio, &ssl);
		if(ssl){
			SSL_set_tlsext_host_name(ssl, u->host);
		}
		*ctx_out = ctx;
		return bio;
	}else{
		return BIO_new_connect(host_port);
	}
}


static unsigned char *read_all(BIO *bio, size_t max_size, size_t *len_out)
{
	const size_t chunk = 4096;
	size_t cap = chunk;
	size_t len = 0;
	unsigned char *buf = mosquitto_malloc(cap);
	if(!buf) return NULL;

	for(;;){
		if(len + chunk > max_size + 1){
			mosquitto_free(buf);
			return NULL;
		}
		if(len + chunk > cap){
			size_t ncap = cap * 2;
			if(ncap > max_size + 1) ncap = max_size + 1;
			unsigned char *nb = mosquitto_realloc(buf, ncap);
			if(!nb){ mosquitto_free(buf); return NULL; }
			buf = nb;
			cap = ncap;
		}
		int r = BIO_read(bio, buf + len, (int)(cap - len));
		if(r > 0){
			len += (size_t)r;
		}else if(r == 0){
			break;
		}else if(!BIO_should_retry(bio)){
			break;
		}
	}

	*len_out = len;
	return buf;
}


/* Split HTTP response into status + headers + body. Returns pointer into
 * `buf` for body start, writes body length to *body_len. Returns NULL on
 * malformed response or non-2xx status. */
static const unsigned char *parse_response(const unsigned char *buf, size_t len,
		size_t *body_len)
{
	const unsigned char *p = buf;
	const unsigned char *end = buf + len;

	const unsigned char *eol = memchr(p, '\n', (size_t)(end - p));
	if(!eol) return NULL;
	if((eol - p) < 12) return NULL;
	int status = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
	if(status < 200 || status > 299) return NULL;

	const unsigned char *body = NULL;
	for(const unsigned char *q = eol + 1; q + 3 < end; q++){
		if(q[0] == '\r' && q[1] == '\n' && q[2] == '\r' && q[3] == '\n'){
			body = q + 4;
			break;
		}
		if(q[0] == '\n' && q[1] == '\n'){
			body = q + 2;
			break;
		}
	}
	if(!body) return NULL;
	*body_len = (size_t)(end - body);
	return body;
}


enum http_fetch_rc http_get(const char *url,
		size_t max_size,
		long timeout_ms,
		unsigned char **body_out,
		size_t *body_len_out)
{
	if(body_out) *body_out = NULL;
	if(body_len_out) *body_len_out = 0;

	if(!url || !body_out || !body_len_out) return HTTP_FETCH_BAD_URL;

	struct parsed_url u;
	if(!parse_http_url(url, &u)){
		return HTTP_FETCH_BAD_URL;
	}

	SSL_CTX *ctx = NULL;
	BIO *bio = open_bio(&u, timeout_ms, &ctx);
	if(!bio){
		parsed_url_free(&u);
		if(ctx) SSL_CTX_free(ctx);
		return HTTP_FETCH_CONNECT_FAILED;
	}

	if(BIO_do_connect(bio) <= 0){
		BIO_free_all(bio);
		if(ctx) SSL_CTX_free(ctx);
		parsed_url_free(&u);
		return HTTP_FETCH_CONNECT_FAILED;
	}

	char req[1024];
	int reqlen = snprintf(req, sizeof(req),
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: mosquitto-cert-rego/1\r\n"
			"Accept: application/pkix-cert, application/x-x509-ca-cert, "
			"application/pkix-crl, application/x-pkcs7-crl, "
			"application/pem-file, */*\r\n"
			"Connection: close\r\n"
			"\r\n",
			u.path, u.host);
	if(reqlen <= 0 || (size_t)reqlen >= sizeof(req)){
		BIO_free_all(bio);
		if(ctx) SSL_CTX_free(ctx);
		parsed_url_free(&u);
		return HTTP_FETCH_BAD_URL;
	}
	if(BIO_write(bio, req, reqlen) != reqlen){
		BIO_free_all(bio);
		if(ctx) SSL_CTX_free(ctx);
		parsed_url_free(&u);
		return HTTP_FETCH_WRITE_FAILED;
	}

	size_t raw_len = 0;
	unsigned char *raw = read_all(bio, max_size, &raw_len);
	BIO_free_all(bio);
	if(ctx) SSL_CTX_free(ctx);
	parsed_url_free(&u);

	if(!raw){
		return HTTP_FETCH_TOO_LARGE; /* either OOM or > cap — both safer as too_large */
	}

	size_t body_len = 0;
	const unsigned char *body = parse_response(raw, raw_len, &body_len);
	if(!body){
		mosquitto_free(raw);
		return HTTP_FETCH_BAD_RESPONSE;
	}

	/* Copy the body into its own allocation so the caller can free with
	 * mosquitto_free, independent of how we allocated the receive buffer. */
	unsigned char *out = mosquitto_malloc(body_len + 1);
	if(!out){
		mosquitto_free(raw);
		return HTTP_FETCH_OOM;
	}
	memcpy(out, body, body_len);
	out[body_len] = '\0';   /* convenience NUL terminator; not part of len */
	mosquitto_free(raw);

	*body_out = out;
	*body_len_out = body_len;
	return HTTP_FETCH_OK;
}
