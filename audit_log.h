/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/
#ifndef CERT_AUTH_AUDIT_LOG_H
#define CERT_AUTH_AUDIT_LOG_H

/*
 * Append-only JSON-lines audit log with two sinks (file + syslog) and a
 * level filter.
 *
 * Levels mirror syslog priorities so the file and syslog representations
 * stay in sync. A level filter is applied before any formatting work, so
 * a DEBUG-only field never costs anything when running at INFO.
 *
 * Each event line is JSON of the form
 *
 *   {"ts":"2026-04-15T07:30:01.123Z","level":"info","event":"connect",
 *    "result":"allow", ...extras...}
 *
 * Extras are an opaque caller-provided JSON fragment — no surrounding braces
 * — already validated by the caller. The audit_log module does not parse it.
 *
 * All emitted lines are clamped to the configured byte cap (default 4 KB).
 * If a line would exceed the cap the body is rebuilt with a `"truncated":true`
 * marker so downstream tooling can flag the loss without reparsing.
 *
 * Rotation of the file sink is expected to be handled externally via
 * logrotate copytruncate. Syslog-side rotation is a problem for the syslog
 * daemon. The audit module never blocks plugin control flow on a sink
 * failure.
 */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct audit_log;

/* Severity ordering matches syslog priorities (lower = more severe). The
 * configured threshold passes/drops events whose level is <= threshold. */
enum audit_level {
	AUDIT_LEVEL_ERROR   = 0,
	AUDIT_LEVEL_WARNING = 1,
	AUDIT_LEVEL_NOTICE  = 2,
	AUDIT_LEVEL_INFO    = 3,
	AUDIT_LEVEL_DEBUG   = 4,
};

/* Per-line limits. Apply during event emission; callers building extras
 * should pass these to the per-field truncation helpers below so that
 * pathological inputs don't break framing.
 *
 * AUDIT_DN_MAX_CHARS — per-DN truncation budget for chain dumps.
 * AUDIT_LINE_DEFAULT — default line cap, matches glibc syslog(3) safe size
 *                      and gives plenty of headroom for rsyslog (8K).
 * AUDIT_LINE_MIN/MAX — operator-configurable bounds. */
#define AUDIT_DN_MAX_CHARS    256
#define AUDIT_LINE_DEFAULT   4096
#define AUDIT_LINE_MIN       1024
#define AUDIT_LINE_MAX      16384

struct audit_log_config {
	/* File sink. NULL or empty disables the file sink. */
	const char *file_path;
	bool fsync_per_line;

	/* Syslog sink. ident defaults to "mosquitto-cert-rego" if NULL.
	 * facility takes a syslog facility name ("auth", "authpriv",
	 * "daemon", "local0".."local7"); NULL → authpriv. */
	bool syslog_enabled;
	const char *syslog_ident;
	const char *syslog_facility;

	/* Threshold filter. Events with level > threshold are dropped before
	 * formatting. Default INFO. */
	enum audit_level level;

	/* Hard per-line cap, in bytes (clamped to [AUDIT_LINE_MIN,
	 * AUDIT_LINE_MAX]). Lines that would exceed this are rebuilt with a
	 * "truncated":true marker. Default AUDIT_LINE_DEFAULT. */
	size_t line_cap_bytes;
};

/* Open the audit log. The config is copied; the caller may free its fields
 * after this returns. If both sinks are disabled (no file, no syslog) the
 * returned handle is a no-op sink. Always returns a valid pointer (or NULL
 * only on OOM); a sink that fails to open is logged via mosquitto_log_printf
 * and the corresponding sink is silently disabled — audit logging must
 * never break the plugin's control flow. */
struct audit_log *audit_log_open(const struct audit_log_config *cfg);

void audit_log_close(struct audit_log *log);
void audit_log_flush(struct audit_log *log);

/* Cheap pre-check for callers that want to skip building expensive extras
 * (chain dumps, SAN serialisation) when the configured level would drop
 * the event anyway. Returns true iff a subsequent audit_log_event_at at
 * the given level would actually emit. */
bool audit_log_enabled(const struct audit_log *log, enum audit_level level);

/* Map a level name to enum. Accepts: "error","warn","warning","notice",
 * "info","debug". Returns false on unknown name (out unchanged). */
bool audit_log_parse_level(const char *name, enum audit_level *out);

/* Emit one event at the given level.
 *
 * level:       severity; events above the configured threshold are dropped.
 * event:       short name, e.g. "connect", "acl", "policy.note",
 *              "plugin.init". Becomes the "event" field.
 * result:      one of "allow", "deny", "error", "ok", or NULL when the
 *              event has no decision component.
 * extras_json: raw JSON object body *without* surrounding braces, already
 *              valid JSON. NULL for no extras. The module does NOT validate
 *              or escape this — callers must escape any untrusted strings
 *              before passing.
 *
 * Output: a single newline-terminated JSON object, written atomically to
 * each enabled sink. If the line would exceed the configured cap, it is
 * rebuilt as a minimal `{"ts":...,"level":...,"event":...,"result":...,
 * "truncated":true}` line and the long extras dropped.
 */
void audit_log_event_at(struct audit_log *log,
		enum audit_level level,
		const char *event,
		const char *result,
		const char *extras_json);

/* Backwards-compatible wrapper. Picks level based on result:
 *   "allow" / "ok"           → INFO
 *   "deny"                   → NOTICE
 *   "error"                  → WARNING
 *   anything else            → INFO
 * Most call sites should prefer audit_log_event_at with an explicit level. */
void audit_log_event(struct audit_log *log,
		const char *event,
		const char *result,
		const char *extras_json);

/*
 * JSON string escape helper. Used by callers building the extras_json
 * fragment — produces a mosquitto_strdup'd buffer with a leading and
 * trailing quote and all interior characters properly escaped per
 * RFC 8259. Returns NULL on OOM. Caller frees with mosquitto_free.
 */
char *audit_log_escape_json_string(const char *s);

/* Like audit_log_escape_json_string but truncates the input to at most
 * `max_chars` UTF-8 code units (not bytes — counting bytes is fine for
 * ASCII DNs which is the common case; we count bytes here and append "…"
 * encoded as the JSON escape `\u2026` if the input was cut). The output
 * stays valid JSON. Used for chain DN dumps to bound the per-cert size.
 *
 * If max_chars is 0 the function behaves like the unbounded escape. */
char *audit_log_escape_json_string_truncated(const char *s, size_t max_chars);

#ifdef __cplusplus
}
#endif
#endif
