/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/
#ifndef CERT_AUTH_AUDIT_LOG_H
#define CERT_AUTH_AUDIT_LOG_H

/*
 * Append-only JSON-lines audit log.
 *
 * One FILE* opened at plugin init, closed at cleanup. Each emitted event is
 * a single line of JSON, so external tooling (logrotate, vector, filebeat)
 * can tail and ship without a second parser. Rotation is expected to be
 * handled externally via logrotate with copytruncate; we fsync-per-line
 * only when the operator explicitly asks, because fsync on every MQTT
 * connect is a throughput killer.
 *
 * The API is intentionally minimal: one call per event. Callers build the
 * key-value pairs themselves; we don't impose a schema so different events
 * can carry different fields without the log library becoming a general-
 * purpose JSON builder.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct audit_log;

/* Open the audit log at the given path. If path is NULL or empty, returns
 * a valid audit_log that is a no-op sink (every audit_log_event call silently
 * returns). If path cannot be opened, logs a warning via mosquitto_log_printf
 * and returns a no-op sink — audit logging must never break the plugin's
 * control flow. */
struct audit_log *audit_log_open(const char *path, bool fsync_per_line);

void audit_log_close(struct audit_log *log);

/*
 * Emit one JSON-line event.
 *
 * event:       required short name, e.g. "connect", "acl", "ldap.search",
 *              "ocsp.query", "policy.reload". Becomes the "event" field.
 * result:      one of "allow", "deny", "error", "hit", "miss", "ok", or
 *              NULL for events without a decision component.
 * extras_json: raw JSON object body *without* surrounding braces, appended
 *              after the standard fields. Must already be a valid JSON
 *              fragment — this module does NOT validate or escape it. If
 *              NULL, no extras are written. Callers that need to embed
 *              untrusted strings should escape them before passing.
 *
 * The emitted line has this shape:
 *   {"ts":"2026-04-11T14:23:01.123Z","event":"connect","result":"allow",
 *    "client_id":"...","cert_fp":"sha256:..."}
 *
 * Timestamp is UTC, millisecond resolution. Events are line-buffered; call
 * audit_log_flush() explicitly before a graceful shutdown if you want to be
 * sure everything hit disk without waiting for close().
 */
void audit_log_event(struct audit_log *log,
		const char *event,
		const char *result,
		const char *extras_json);

void audit_log_flush(struct audit_log *log);

/*
 * JSON string escape helper. Used by callers building the extras_json
 * fragment — produces a mosquitto_strdup'd buffer with a leading and
 * trailing quote and all interior characters properly escaped per
 * RFC 8259. Returns NULL on OOM. Caller frees with mosquitto_free.
 *
 * The plugin uses this rather than cJSON because the audit log is the one
 * hot path where pulling in a JSON builder would add latency on every auth
 * decision; we're only ever writing, never parsing, so hand-escape is fine.
 */
char *audit_log_escape_json_string(const char *s);

#ifdef __cplusplus
}
#endif
#endif
