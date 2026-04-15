/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/
#ifndef CERT_AUTH_REGO_ENGINE_H
#define CERT_AUTH_REGO_ENGINE_H

/*
 * Plain-C façade over the rego-cpp Interpreter. The only TU that actually
 * includes <rego/rego.hh> is rego_engine.cpp; every other translation unit
 * in the plugin stays in C-land and goes through this header.
 *
 * Lifecycle:
 *   struct rego_engine *e = rego_engine_new(plg, "policy.rego");
 *   ... per connect / per acl ...
 *   rego_engine_eval_bool(e, "data.mqtt.connect.allow", input_json, &allow);
 *   ... on SIGHUP ...
 *   rego_engine_reload(e, "policy.rego");
 *   ... on shutdown ...
 *   rego_engine_drop(e);
 *
 * Thread-safety: single-threaded only. mosquitto runs its plugin callbacks
 * on the main loop thread so this is not a practical limitation. The LDAP
 * callbacks registered with rego-cpp pull the ca_plugin pointer from a
 * file-scope static inside rego_engine.cpp, set when the engine is
 * constructed.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ca_plugin;

struct rego_engine;

/* Create a new engine, load the policy file, register LDAP builtins.
 * Returns NULL and logs via mosquitto_log_printf on any failure (missing
 * file, parse error, builtin registration error). On success, plg is
 * retained by the engine (via a file-scope static for builtin dispatch). */
struct rego_engine *rego_engine_new(struct ca_plugin *plg,
		const char *policy_file);

/* Hot-reload: parse a fresh policy file into a new Interpreter and atomically
 * swap it in. Returns 0 on success, -1 on any error — on error the existing
 * policy stays active (fail-safe). */
int rego_engine_reload(struct rego_engine *e, const char *policy_file);

/* Evaluate a boolean rule (e.g. "data.mqtt.connect.allow") with the given
 * JSON input string. Sets *allow_out to true iff the rule evaluates to
 * exactly `true`. Any other result (undefined, false, non-boolean, parse
 * error, eval panic) sets *allow_out to false and returns -1.
 *
 * Returns 0 on a clean true/false evaluation, -1 on any error.
 */
int rego_engine_eval_bool(struct rego_engine *e,
		const char *entrypoint,
		const char *input_json,
		bool *allow_out);

/* Same as rego_engine_eval_bool, but stashes the verified X509 chain in
 * per-eval state so that the ocsp.check() host function (invoked from
 * inside the policy) can walk it.
 *
 * `chain` is a STACK_OF(X509) * — declared as void * here so this header
 * stays free of OpenSSL includes. Valid only for the duration of this
 * call; the stash is cleared before return so subsequent evaluations
 * that don't have a chain cannot observe a stale pointer.
 */
int rego_engine_eval_bool_with_chain(struct rego_engine *e,
		const char *entrypoint,
		const char *input_json,
		void *chain,
		bool *allow_out);

void rego_engine_drop(struct rego_engine *e);

#ifdef __cplusplus
}
#endif
#endif
