/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#ifndef WIN32
#  include <unistd.h>
#endif

#include <mosquitto.h>

#include "audit_log.h"


struct audit_log {
	FILE *fp;
	int fd;                 /* dup of fileno(fp) for fsync, or -1 if no file */
	bool fsync_per_line;
};


static struct audit_log *audit_log_noop(void)
{
	struct audit_log *log = mosquitto_calloc(1, sizeof(*log));
	if(log){
		log->fp = NULL;
		log->fd = -1;
		log->fsync_per_line = false;
	}
	return log;
}


struct audit_log *audit_log_open(const char *path, bool fsync_per_line)
{
	struct audit_log *log;

	if(path == NULL || path[0] == '\0'){
		return audit_log_noop();
	}

	log = mosquitto_calloc(1, sizeof(*log));
	if(!log) return NULL;

	log->fp = fopen(path, "ae"); /* "a" = append, "e" = O_CLOEXEC (glibc) */
	if(!log->fp){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: unable to open audit log '%s': %s — audit disabled",
				path, strerror(errno));
		log->fp = NULL;
		log->fd = -1;
		log->fsync_per_line = false;
		return log;
	}

	/* Line-buffered so partial writes don't interleave when logrotate
	 * copytruncates the file out from under us. */
	setvbuf(log->fp, NULL, _IOLBF, 0);

	log->fd = fileno(log->fp);
	log->fsync_per_line = fsync_per_line;

	mosquitto_log_printf(MOSQ_LOG_INFO,
			"cert-rego: audit log opened at %s (fsync_per_line=%s)",
			path, fsync_per_line ? "true" : "false");
	return log;
}


void audit_log_close(struct audit_log *log)
{
	if(!log) return;
	if(log->fp){
		fflush(log->fp);
		fclose(log->fp);
	}
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


/* ---- JSON escape ------------------------------------------------------- */

static size_t json_escape_worst_case(const char *s)
{
	/* Worst case: every byte is escaped as \u00XX (6 chars) + 2 quotes + NUL. */
	size_t n = 0;
	while(s[n]) n++;
	return n * 6 + 3;
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
		unsigned char c = *p;
		switch(c){
			case '"':  out[w++] = '\\'; out[w++] = '"';  break;
			case '\\': out[w++] = '\\'; out[w++] = '\\'; break;
			case '\b': out[w++] = '\\'; out[w++] = 'b';  break;
			case '\f': out[w++] = '\\'; out[w++] = 'f';  break;
			case '\n': out[w++] = '\\'; out[w++] = 'n';  break;
			case '\r': out[w++] = '\\'; out[w++] = 'r';  break;
			case '\t': out[w++] = '\\'; out[w++] = 't';  break;
			default:
				if(c < 0x20){
					w += (size_t)snprintf(out + w, 7, "\\u%04x", c);
				}else{
					out[w++] = (char)c;
				}
		}
	}
	out[w++] = '"';
	out[w] = '\0';
	return out;
}


/* ---- Event emission ---------------------------------------------------- */

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
	/* tv.tv_usec is documented to be 0..999999; divide to get milliseconds
	 * and clamp explicitly so the compiler's format-overflow analysis is
	 * happy across all platforms. */
	long ms = (long)(tv.tv_usec / 1000);
	if(ms < 0) ms = 0;
	if(ms > 999) ms = 999;
	snprintf(buf, buflen,
			"%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			ms);
}


void audit_log_event(struct audit_log *log,
		const char *event,
		const char *result,
		const char *extras_json)
{
	if(!log || !log->fp || !event) return;

	char ts[40];
	format_iso8601_utc_ms(ts, sizeof(ts));

	/* We write each line with a single fprintf so that line buffering
	 * produces one atomic write on POSIX (assuming the line fits within
	 * PIPE_BUF / the stdio buffer). The format is stable and parsed by
	 * downstream tooling; do not reorder fields without a major version. */
	if(result && extras_json){
		fprintf(log->fp,
				"{\"ts\":\"%s\",\"event\":\"%s\",\"result\":\"%s\",%s}\n",
				ts, event, result, extras_json);
	}else if(result){
		fprintf(log->fp,
				"{\"ts\":\"%s\",\"event\":\"%s\",\"result\":\"%s\"}\n",
				ts, event, result);
	}else if(extras_json){
		fprintf(log->fp,
				"{\"ts\":\"%s\",\"event\":\"%s\",%s}\n",
				ts, event, extras_json);
	}else{
		fprintf(log->fp,
				"{\"ts\":\"%s\",\"event\":\"%s\"}\n",
				ts, event);
	}

	if(log->fsync_per_line && log->fd >= 0){
		fflush(log->fp);
		(void)fsync(log->fd);
	}
}
