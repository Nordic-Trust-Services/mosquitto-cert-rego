/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/
#ifndef CERT_AUTH_HTTP_FETCH_H
#define CERT_AUTH_HTTP_FETCH_H

/*
 * Minimal HTTP/HTTPS GET helper used by the AIA and CRL fetchers.
 *
 * The goal is to keep the "pull bytes from a URL embedded in a cert"
 * primitive in one place so the security posture (scheme whitelist,
 * size cap, no redirects, timeout, TLS with system trust) is consistent
 * between modules.
 */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum http_fetch_rc {
	HTTP_FETCH_OK = 0,
	HTTP_FETCH_BAD_URL,            /* scheme not http/https, malformed */
	HTTP_FETCH_CONNECT_FAILED,
	HTTP_FETCH_WRITE_FAILED,
	HTTP_FETCH_READ_FAILED,
	HTTP_FETCH_TOO_LARGE,          /* body exceeded max_size */
	HTTP_FETCH_BAD_RESPONSE,       /* non-2xx or malformed HTTP reply */
	HTTP_FETCH_OOM,
};

const char *http_fetch_rc_str(enum http_fetch_rc rc);

/*
 * GET `url`, returning the response body in *body_out / *body_len_out.
 * Caller frees *body_out with mosquitto_free. max_size is a hard cap on
 * the body; exceeding it returns HTTP_FETCH_TOO_LARGE. timeout_ms is
 * honoured at the TCP level (approximately).
 *
 * Only http:// and https:// URLs are accepted. Redirects are not
 * followed. HTTPS uses the system default trust store.
 *
 * Logs go through mosquitto_log_printf; the caller just checks the rc.
 */
enum http_fetch_rc http_get(const char *url,
		size_t max_size,
		long timeout_ms,
		unsigned char **body_out,
		size_t *body_len_out);

#ifdef __cplusplus
}
#endif
#endif
