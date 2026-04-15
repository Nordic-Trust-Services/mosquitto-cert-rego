/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>

#ifndef WIN32
#  include <syslog.h>
#  include <unistd.h>
#endif

#include <mosquitto.h>

#include "audit_log.h"


struct audit_log {
	/* File sink. fp NULL means "no file sink". */
	FILE *fp;
	int fd;                 /* dup of fileno(fp), or -1 */
	bool fsync_per_line;

	/* Syslog sink. ident_owned is the strdup'd buffer passed to openlog,
	 * which keeps a pointer to it for the process's lifetime — so we must
	 * hand it stable storage and never free it before closelog(). */
	bool syslog_open;
	char *ident_owned;
	int syslog_facility;

	enum audit_level level;
	size_t line_cap;
};


/* ---- helpers ---------------------------------------------------------- */

#ifndef WIN32
/* Mapping from our levels to syslog priorities. */
static int level_to_syslog(enum audit_level lv)
{
	switch(lv){
		case AUDIT_LEVEL_ERROR:   return LOG_ERR;
		case AUDIT_LEVEL_WARNING: return LOG_WARNING;
		case AUDIT_LEVEL_NOTICE:  return LOG_NOTICE;
		case AUDIT_LEVEL_INFO:    return LOG_INFO;
		case AUDIT_LEVEL_DEBUG:   return LOG_DEBUG;
	}
	return LOG_INFO;
}

static int parse_facility(const char *name)
{
	if(!name || !*name) return LOG_AUTHPRIV;
	if(!strcasecmp(name, "auth"))     return LOG_AUTH;
	if(!strcasecmp(name, "authpriv")) return LOG_AUTHPRIV;
	if(!strcasecmp(name, "daemon"))   return LOG_DAEMON;
	if(!strcasecmp(name, "user"))     return LOG_USER;
	if(!strcasecmp(name, "local0"))   return LOG_LOCAL0;
	if(!strcasecmp(name, "local1"))   return LOG_LOCAL1;
	if(!strcasecmp(name, "local2"))   return LOG_LOCAL2;
	if(!strcasecmp(name, "local3"))   return LOG_LOCAL3;
	if(!strcasecmp(name, "local4"))   return LOG_LOCAL4;
	if(!strcasecmp(name, "local5"))   return LOG_LOCAL5;
	if(!strcasecmp(name, "local6"))   return LOG_LOCAL6;
	if(!strcasecmp(name, "local7"))   return LOG_LOCAL7;
	mosquitto_log_printf(MOSQ_LOG_WARNING,
			"cert-rego: unknown syslog facility '%s', using authpriv", name);
	return LOG_AUTHPRIV;
}
#endif

static const char *level_name(enum audit_level lv)
{
	switch(lv){
		case AUDIT_LEVEL_ERROR:   return "error";
		case AUDIT_LEVEL_WARNING: return "warning";
		case AUDIT_LEVEL_NOTICE:  return "notice";
		case AUDIT_LEVEL_INFO:    return "info";
		case AUDIT_LEVEL_DEBUG:   return "debug";
	}
	return "info";
}

bool audit_log_parse_level(const char *name, enum audit_level *out)
{
	if(!name || !out) return false;
	if(!strcasecmp(name, "error"))   { *out = AUDIT_LEVEL_ERROR;   return true; }
	if(!strcasecmp(name, "warn"))    { *out = AUDIT_LEVEL_WARNING; return true; }
	if(!strcasecmp(name, "warning")) { *out = AUDIT_LEVEL_WARNING; return true; }
	if(!strcasecmp(name, "notice"))  { *out = AUDIT_LEVEL_NOTICE;  return true; }
	if(!strcasecmp(name, "info"))    { *out = AUDIT_LEVEL_INFO;    return true; }
	if(!strcasecmp(name, "debug"))   { *out = AUDIT_LEVEL_DEBUG;   return true; }
	return false;
}


/* ---- open / close ----------------------------------------------------- */

struct audit_log *audit_log_open(const struct audit_log_config *cfg)
{
	struct audit_log *log = mosquitto_calloc(1, sizeof(*log));
	if(!log) return NULL;

	log->fd = -1;
	log->level = cfg ? cfg->level : AUDIT_LEVEL_INFO;
	log->line_cap = (cfg && cfg->line_cap_bytes) ? cfg->line_cap_bytes : AUDIT_LINE_DEFAULT;
	if(log->line_cap < AUDIT_LINE_MIN) log->line_cap = AUDIT_LINE_MIN;
	if(log->line_cap > AUDIT_LINE_MAX) log->line_cap = AUDIT_LINE_MAX;

	if(cfg && cfg->file_path && cfg->file_path[0]){
		log->fp = fopen(cfg->file_path, "ae"); /* "a"=append, "e"=O_CLOEXEC */
		if(!log->fp){
			mosquitto_log_printf(MOSQ_LOG_WARNING,
					"cert-rego: unable to open audit log '%s': %s — file sink disabled",
					cfg->file_path, strerror(errno));
		}else{
			setvbuf(log->fp, NULL, _IOLBF, 0);
			log->fd = fileno(log->fp);
			log->fsync_per_line = cfg->fsync_per_line;
			mosquitto_log_printf(MOSQ_LOG_INFO,
					"cert-rego: audit file sink at %s (fsync_per_line=%s)",
					cfg->file_path, cfg->fsync_per_line ? "true" : "false");
		}
	}

#ifndef WIN32
	if(cfg && cfg->syslog_enabled){
		const char *ident = (cfg->syslog_ident && cfg->syslog_ident[0])
			? cfg->syslog_ident : "mosquitto-cert-rego";
		log->ident_owned = mosquitto_strdup(ident);
		if(!log->ident_owned){
			mosquitto_log_printf(MOSQ_LOG_WARNING,
					"cert-rego: OOM allocating syslog ident — syslog sink disabled");
		}else{
			log->syslog_facility = parse_facility(cfg->syslog_facility);
			openlog(log->ident_owned, LOG_PID | LOG_NDELAY, log->syslog_facility);
			log->syslog_open = true;
			mosquitto_log_printf(MOSQ_LOG_INFO,
					"cert-rego: audit syslog sink open (ident=%s)",
					log->ident_owned);
		}
	}
#endif

	mosquitto_log_printf(MOSQ_LOG_INFO,
			"cert-rego: audit level=%s, line_cap=%zu",
			level_name(log->level), log->line_cap);
	return log;
}


void audit_log_close(struct audit_log *log)
{
	if(!log) return;
	if(log->fp){
		fflush(log->fp);
		fclose(log->fp);
	}
#ifndef WIN32
	if(log->syslog_open){
		closelog();
	}
#endif
	mosquitto_free(log->ident_owned);
	mosquitto_free(log);
}


void audit_log_flush(struct audit_log *log)
{
	if(!log || !log->fp) return;
	fflush(log->fp);
	if(log->fd >= 0){
		(void)fsync(log->fd);
	}
}


bool audit_log_enabled(const struct audit_log *log, enum audit_level level)
{
	if(!log) return false;
	return level <= log->level;
}


/* ---- JSON escape ------------------------------------------------------- */

static size_t json_escape_worst_case(const char *s)
{
	/* Worst case: every byte is escaped as \u00XX (6 chars) + 2 quotes + NUL. */
	size_t n = 0;
	while(s[n]) n++;
	return n * 6 + 3;
}


static void escape_byte_into(char *out, size_t *w, unsigned char c)
{
	switch(c){
		case '"':  out[(*w)++] = '\\'; out[(*w)++] = '"';  break;
		case '\\': out[(*w)++] = '\\'; out[(*w)++] = '\\'; break;
		case '\b': out[(*w)++] = '\\'; out[(*w)++] = 'b';  break;
		case '\f': out[(*w)++] = '\\'; out[(*w)++] = 'f';  break;
		case '\n': out[(*w)++] = '\\'; out[(*w)++] = 'n';  break;
		case '\r': out[(*w)++] = '\\'; out[(*w)++] = 'r';  break;
		case '\t': out[(*w)++] = '\\'; out[(*w)++] = 't';  break;
		default:
			if(c < 0x20){
				*w += (size_t)snprintf(out + *w, 7, "\\u%04x", c);
			}else{
				out[(*w)++] = (char)c;
			}
	}
}


char *audit_log_escape_json_string(const char *s)
{
	if(!s) return mosquitto_strdup("null");

	size_t cap = json_escape_worst_case(s);
	char *out = mosquitto_malloc(cap);
	if(!out) return NULL;

	size_t w = 0;
	out[w++] = '"';
	for(const unsigned char *p = (const unsigned char *)s; *p; p++){
		escape_byte_into(out, &w, *p);
	}
	out[w++] = '"';
	out[w] = '\0';
	return out;
}


char *audit_log_escape_json_string_truncated(const char *s, size_t max_chars)
{
	if(!s) return mosquitto_strdup("null");
	if(max_chars == 0) return audit_log_escape_json_string(s);

	size_t in_len = strlen(s);
	bool truncated = false;
	if(in_len > max_chars){
		in_len = max_chars;
		truncated = true;
	}

	/* Worst-case: 6 bytes per byte + quotes + NUL + ellipsis (3 utf-8 bytes
	 * "…" → 3 bytes in JSON when ASCII-escaped to \u2026 = 6). */
	size_t cap = in_len * 6 + 16;
	char *out = mosquitto_malloc(cap);
	if(!out) return NULL;

	size_t w = 0;
	out[w++] = '"';
	for(size_t i = 0; i < in_len; i++){
		escape_byte_into(out, &w, (unsigned char)s[i]);
	}
	if(truncated){
		const char *ell = "\\u2026"; /* … */
		while(*ell) out[w++] = *ell++;
	}
	out[w++] = '"';
	out[w] = '\0';
	return out;
}


/* ---- timestamp -------------------------------------------------------- */

static void format_iso8601_utc_ms(char *buf, size_t buflen)
{
	struct timeval tv;
	struct tm tm;

	gettimeofday(&tv, NULL);
#ifdef WIN32
	time_t t = tv.tv_sec;
	gmtime_s(&tm, &t);
#else
	gmtime_r(&tv.tv_sec, &tm);
#endif
	long ms = (long)(tv.tv_usec / 1000);
	if(ms < 0) ms = 0;
	if(ms > 999) ms = 999;
	snprintf(buf, buflen,
			"%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			ms);
}


/* ---- emission --------------------------------------------------------- */

/* Build the JSON line into a caller-supplied buffer. Returns the number of
 * bytes written excluding the terminating NUL and excluding the trailing
 * newline (which is appended only on the file sink — syslog adds its own
 * framing). Returns -1 if the output would exceed cap. */
static int format_event_line(char *buf, size_t cap,
		const char *ts, const char *lvl, const char *event,
		const char *result, const char *extras_json)
{
	int n;
	if(result && extras_json){
		n = snprintf(buf, cap,
				"{\"ts\":\"%s\",\"level\":\"%s\",\"event\":\"%s\","
				"\"result\":\"%s\",%s}",
				ts, lvl, event, result, extras_json);
	}else if(result){
		n = snprintf(buf, cap,
				"{\"ts\":\"%s\",\"level\":\"%s\",\"event\":\"%s\","
				"\"result\":\"%s\"}",
				ts, lvl, event, result);
	}else if(extras_json){
		n = snprintf(buf, cap,
				"{\"ts\":\"%s\",\"level\":\"%s\",\"event\":\"%s\",%s}",
				ts, lvl, event, extras_json);
	}else{
		n = snprintf(buf, cap,
				"{\"ts\":\"%s\",\"level\":\"%s\",\"event\":\"%s\"}",
				ts, lvl, event);
	}
	if(n < 0 || (size_t)n >= cap) return -1;
	return n;
}


void audit_log_event_at(struct audit_log *log,
		enum audit_level level,
		const char *event,
		const char *result,
		const char *extras_json)
{
	if(!log || !event) return;
	if(level > log->level) return;
	if(!log->fp && !log->syslog_open) return;

	char ts[40];
	format_iso8601_utc_ms(ts, sizeof(ts));
	const char *lvl = level_name(level);

	/* Stack buffer up to 4 KB; for larger caps we allocate. */
	char stack_buf[4096];
	char *line = stack_buf;
	size_t cap = log->line_cap;
	bool heap = false;
	if(cap > sizeof(stack_buf)){
		line = mosquitto_malloc(cap);
		if(!line){
			line = stack_buf;
			cap = sizeof(stack_buf);
		}else{
			heap = true;
		}
	}else{
		cap = sizeof(stack_buf);
		if(cap > log->line_cap) cap = log->line_cap;
	}

	int n = format_event_line(line, cap, ts, lvl, event, result, extras_json);
	if(n < 0){
		/* Over the cap. Re-emit a minimal line with truncation marker. The
		 * minimal line carries no extras — operators get the timestamp,
		 * level, event, result and the explicit truncation flag. */
		n = format_event_line(line, cap, ts, lvl, event, result,
				"\"truncated\":true");
		if(n < 0){
			/* Even the minimal form doesn't fit (cap < ~150 bytes which is
			 * impossible given AUDIT_LINE_MIN). Drop the line. */
			if(heap) mosquitto_free(line);
			return;
		}
	}

	if(log->fp){
		fwrite(line, 1, (size_t)n, log->fp);
		fputc('\n', log->fp);
		if(log->fsync_per_line && log->fd >= 0){
			fflush(log->fp);
			(void)fsync(log->fd);
		}
	}

#ifndef WIN32
	if(log->syslog_open){
		syslog(level_to_syslog(level), "%s", line);
	}
#endif

	if(heap) mosquitto_free(line);
}


void audit_log_event(struct audit_log *log,
		const char *event,
		const char *result,
		const char *extras_json)
{
	enum audit_level lv = AUDIT_LEVEL_INFO;
	if(result){
		if(!strcmp(result, "deny"))       lv = AUDIT_LEVEL_NOTICE;
		else if(!strcmp(result, "error")) lv = AUDIT_LEVEL_WARNING;
	}
	audit_log_event_at(log, lv, event, result, extras_json);
}
