/*
 * Runtime stubs for the cert-rego test harness.
 *
 * When the plugin is loaded by a real mosquitto broker, symbols like
 * mosquitto_calloc and mosquitto_log_printf are provided by the broker
 * process. For a standalone test binary that exercises rego_engine.cpp
 * (and its C dependencies) without a broker, we provide trivial shims
 * that delegate to libc and stderr.
 *
 * These stubs are ONLY linked into tests, never into the production .so.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- memory ------------------------------------------------------------ */

void *mosquitto_malloc(size_t n) { return malloc(n); }
void *mosquitto_calloc(size_t n, size_t s) { return calloc(n, s); }
void *mosquitto_realloc(void *p, size_t n) { return realloc(p, n); }
void  mosquitto_free(void *p) { free(p); }

char *mosquitto_strdup(const char *s)
{
	if(!s) return NULL;
	size_t n = strlen(s);
	char *out = malloc(n + 1);
	if(out) memcpy(out, s, n + 1);
	return out;
}

/* ---- logging ----------------------------------------------------------- */

void mosquitto_log_printf(int level, const char *fmt, ...)
{
	(void)level;
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "[plugin-test] ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}
