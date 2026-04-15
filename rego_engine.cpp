/*
Copyright (c) 2026 Cedalo Ltd
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

/*
 * rego_engine: the single C++ translation unit in the plugin.
 *
 * Wraps rego-cpp's Interpreter with a plain-C façade declared in
 * rego_engine.h. Registers the four ldap.* custom built-ins and dispatches
 * them into ldap_query.c via extern "C" calls.
 *
 * rego-cpp API notes (verified against rego-cpp main branch, 2026-04):
 *
 *   - Built-ins are free functions of type `Node (*)(const Nodes&)`, no
 *     user_data slot. We stash the plugin pointer in a file-scope static
 *     set during rego_engine_new.
 *
 *   - Interpreter::add_module_file, set_input_json, and add_data_json all
 *     return a Node — an error-type Node on failure, something else on
 *     success. Check via `node->type() == Error`.
 *
 *   - Query evaluation uses query_output which returns an Output object.
 *     The Output exposes ok(), size(), and expressions() — for a boolean
 *     rule we read the last expression and feed it to get_bool().
 *
 *   - String arguments: unwrap_arg with UnwrapOpt(i).type(JSONString),
 *     check `node->type() == Error` for type mismatch, then get_string
 *     which already strips the surrounding JSON quotes.
 *
 *   - Return values: boolean(bool), string(std::string) — scalar(T) is
 *     deprecated in the current header.
 *
 *   - ldap.search returns a JSON string. Policies can parse it with the
 *     built-in json.unmarshal to get an array of objects. Doing it this
 *     way avoids building Trieste Node trees on the C++ side.
 */

#include <cstring>
#include <memory>
#include <mutex>
#include <string>

#include <rego/rego.hh>

#include <mosquitto.h>

extern "C" {
#include "cert_auth.h"
#include "audit_log.h"
#include "ldap_query.h"
#include "rego_engine.h"
}

using rego::Interpreter;
using rego::Node;
using rego::Nodes;
using rego::BuiltInDef;
using rego::Location;
using rego::UnwrapOpt;
using rego::Error;
using rego::JSONString;
using rego::EvalBuiltInError;

namespace bi = rego::builtins;

namespace {

/* File-scope plugin pointer. Set by rego_engine_new, read by the ldap.*
 * and ocsp.check() callbacks. Single-instance assumption documented in
 * the header. */
static struct ca_plugin *g_plugin = nullptr;

/* Per-evaluation chain pointer. Set by rego_engine_eval_bool_with_chain
 * around the eval call, cleared before return. Read by the ocsp.check()
 * host function so a policy can walk the client's verified chain without
 * passing the chain (which has no natural Rego representation) as an
 * argument. NULL means "no chain available" — ocsp.check() returns an
 * error Node in that case. */
static STACK_OF(X509) *g_current_chain = nullptr;


/* Extract a single string argument by index. On any failure returns the
 * error Node unwrap_arg produced; callers propagate it up as the builtin's
 * return value so rego-cpp reports a well-shaped builtin error. */
static Node unwrap_string(const Nodes& args, std::size_t idx, std::string& out)
{
	Node a = rego::unwrap_arg(args, UnwrapOpt(idx).type(JSONString));
	if(a->type() == Error){
		return a;
	}
	out = rego::get_string(a);
	return nullptr;  /* null means success */
}


/* Build a fresh error Node anchored on an argument of the call. */
static Node make_error(const Nodes& args, const std::string& msg)
{
	Node anchor = args.empty() ? Node{} : args[0];
	return rego::err(anchor, msg, EvalBuiltInError);
}


/* NOTE: ldap.login intentionally does not exist.
 *
 * This plugin is passwordless — client authentication is certificate-based
 * and MQTT CONNECT passwords are never forwarded to LDAP. The Rego
 * host-function set exposed here is read-only directory access:
 *   ldap.search     — attribute retrieval
 *   ldap.exists     — presence check
 *   ldap.is_member  — group membership check
 * All three bind to the directory using the plugin's service-account
 * credentials (plugin config), not any user-supplied credential.
 *
 * For OAuth2 token introspection or arbitrary HTTP lookups, policies use
 * rego-cpp's built-in http.send. For OS-user lookups, add a new host
 * function here following the ldap.* pattern. */


/* ---- ldap.search ---------------------------------------------------- */

static Node builtin_ldap_search(const Nodes& args)
{
	if(!g_plugin) return make_error(args, "ldap.search: plugin not initialised");

	std::string url, bind_dn, bind_pw, base_dn, scope, filter, attrs;
	if(Node e = unwrap_string(args, 0, url); e) return e;
	if(Node e = unwrap_string(args, 1, bind_dn); e) return e;
	if(Node e = unwrap_string(args, 2, bind_pw); e) return e;
	if(Node e = unwrap_string(args, 3, base_dn); e) return e;
	if(Node e = unwrap_string(args, 4, scope); e) return e;
	if(Node e = unwrap_string(args, 5, filter); e) return e;
	if(Node e = unwrap_string(args, 6, attrs); e) return e;

	struct ldap_ctx ctx;
	ctx.cfg = &g_plugin->cfg.ldap;
	ctx.cache = g_plugin->cache;
	ctx.audit = g_plugin->audit;

	char *json_out = nullptr;
	enum ldap_query_rc rc = ldap_query_search(
			&ctx, url.c_str(), bind_dn.c_str(), bind_pw.c_str(),
			base_dn.c_str(), scope.c_str(), filter.c_str(),
			attrs.empty() ? nullptr : attrs.c_str(),
			&json_out);
	if(rc != LDAP_Q_OK || !json_out){
		if(json_out) mosquitto_free(json_out);
		return make_error(args, std::string("ldap.search: ") + ldap_query_rc_str(rc));
	}

	std::string s(json_out);
	mosquitto_free(json_out);

	/* Return as a JSON string. Policies call `json.unmarshal(ldap.search(...))`
	 * to get the structured result. This avoids building Trieste Node trees
	 * on the C++ side — rego-cpp's own JSON parser does the conversion from
	 * inside the policy. */
	return rego::string(s);
}


/* ---- ldap.exists ---------------------------------------------------- */

static Node builtin_ldap_exists(const Nodes& args)
{
	if(!g_plugin) return make_error(args, "ldap.exists: plugin not initialised");

	std::string url, bind_dn, bind_pw, base_dn, filter;
	if(Node e = unwrap_string(args, 0, url); e) return e;
	if(Node e = unwrap_string(args, 1, bind_dn); e) return e;
	if(Node e = unwrap_string(args, 2, bind_pw); e) return e;
	if(Node e = unwrap_string(args, 3, base_dn); e) return e;
	if(Node e = unwrap_string(args, 4, filter); e) return e;

	struct ldap_ctx ctx;
	ctx.cfg = &g_plugin->cfg.ldap;
	ctx.cache = g_plugin->cache;
	ctx.audit = g_plugin->audit;

	bool result = false;
	enum ldap_query_rc rc = ldap_query_exists(
			&ctx, url.c_str(), bind_dn.c_str(), bind_pw.c_str(),
			base_dn.c_str(), filter.c_str(), &result);
	if(rc != LDAP_Q_OK){
		return make_error(args, std::string("ldap.exists: ") + ldap_query_rc_str(rc));
	}
	return rego::boolean(result);
}


/* ---- ldap.is_member ------------------------------------------------- */

static Node builtin_ldap_is_member(const Nodes& args)
{
	if(!g_plugin) return make_error(args, "ldap.is_member: plugin not initialised");

	std::string url, bind_dn, bind_pw, group_dn, user_dn;
	if(Node e = unwrap_string(args, 0, url); e) return e;
	if(Node e = unwrap_string(args, 1, bind_dn); e) return e;
	if(Node e = unwrap_string(args, 2, bind_pw); e) return e;
	if(Node e = unwrap_string(args, 3, group_dn); e) return e;
	if(Node e = unwrap_string(args, 4, user_dn); e) return e;

	struct ldap_ctx ctx;
	ctx.cfg = &g_plugin->cfg.ldap;
	ctx.cache = g_plugin->cache;
	ctx.audit = g_plugin->audit;

	bool result = false;
	enum ldap_query_rc rc = ldap_query_is_member(
			&ctx, url.c_str(), bind_dn.c_str(), bind_pw.c_str(),
			group_dn.c_str(), user_dn.c_str(), &result);
	if(rc != LDAP_Q_OK){
		return make_error(args, std::string("ldap.is_member: ") + ldap_query_rc_str(rc));
	}
	return rego::boolean(result);
}


/* ---- ocsp.check -------------------------------------------------------
 *
 * Takes no arguments. Returns a JSON string that the policy is expected to
 * `json.unmarshal` into an array of per-cert status objects:
 *
 *   [
 *     {"depth":0, "subject_dn":"CN=...", "status":"good",
 *      "cached":true, "error":null},
 *     {"depth":1, "subject_dn":"CN=...", "status":"good",
 *      "cached":false, "error":null},
 *     {"depth":2, "subject_dn":"CN=Root", "status":"skipped_root",
 *      "cached":false, "error":null}
 *   ]
 *
 * status is one of: good / revoked / unknown / error / skipped_root /
 * no_issuer / no_aia. The policy decides which combinations of these
 * constitute "allow" — strict mode, soft-fail mode, leaf-only mode, all
 * of those become different Rego expressions rather than plugin config.
 *
 * A request invoked when no verified chain is in scope (i.e. not called
 * from inside the cert-auth connect/ACL eval) returns an error Node; in
 * fail-closed policies that evaluates to deny, which is the right default.
 */

static Node builtin_ocsp_check(const Nodes& args)
{
	if(!g_plugin) return make_error(args, "ocsp.check: plugin not initialised");
	if(!g_current_chain){
		return make_error(args, "ocsp.check: no verified chain in scope");
	}

	char *json_out = ca_ocsp_inspect_json(g_plugin, g_current_chain);
	if(!json_out){
		return make_error(args, "ocsp.check: out of memory");
	}
	std::string s(json_out);
	mosquitto_free(json_out);

	/* Return as a JSON string — policies call json.unmarshal to get the
	 * structured array. Same convention as ldap.search. */
	return rego::string(s);
}


/* ---- crl.check --------------------------------------------------------
 *
 * No arguments. Returns a JSON string — policies json.unmarshal it into
 * an array of per-cert CRL status objects:
 *
 *   [
 *     {"depth":0, "subject_dn":"CN=...", "status":"good",
 *      "cached":true, "error":null},
 *     {"depth":1, "subject_dn":"CN=...", "status":"revoked",
 *      "cached":false, "error":null},
 *     ...
 *   ]
 *
 * status one of: good / revoked / expired_crl / unknown / error /
 * skipped_root / no_dp / bad_sig. Policies decide semantics.
 *
 * Returns an error Node if called without a chain in scope (not invoked
 * from inside the cert-auth flow) — under fail-closed that evaluates to
 * deny, which is the safest default.
 */

static Node builtin_crl_check(const Nodes& args)
{
	if(!g_plugin) return make_error(args, "crl.check: plugin not initialised");
	if(!g_current_chain){
		return make_error(args, "crl.check: no verified chain in scope");
	}

	char *json_out = ca_crl_inspect_json(g_plugin, g_current_chain);
	if(!json_out){
		return make_error(args, "crl.check: out of memory");
	}
	std::string s(json_out);
	mosquitto_free(json_out);
	return rego::string(s);
}


/* audit.log(message_string)
 *
 * Lets a Rego policy attach a free-form note to the audit trail — typically
 * the reason an unusual decision was made (e.g. "override accepted: expired
 * intermediate during root rotation"). Emitted as a `policy.note` event at
 * DEBUG level so it doesn't pollute INFO logging unless the operator opts in.
 *
 * The argument can be any string — policies wanting structured data should
 * pass json.marshal(obj) and audit consumers can re-parse it.
 *
 * Returns true on success so policies can compose it inline:
 *   allow { ...; audit.log("override:expired_intermediate") }
 */
static Node builtin_audit_log(const Nodes& args)
{
	if(!g_plugin || !g_plugin->audit){
		/* No audit sink — return true so the policy still composes cleanly. */
		return rego::boolean(true);
	}

	std::string msg;
	Node err = unwrap_string(args, 0, msg);
	if(err) return err;

	if(msg.size() > 1024) msg.resize(1024);

	char *esc = audit_log_escape_json_string(msg.c_str());
	if(!esc) return rego::boolean(true);

	std::string extras = "\"note\":";
	extras += esc;
	mosquitto_free(esc);

	audit_log_event_at(g_plugin->audit, AUDIT_LEVEL_DEBUG,
			"policy.note", nullptr, extras.c_str());
	return rego::boolean(true);
}


/* ---- Declaration builders ------------------------------------------- */

/* Build a Decl node with N string args and a boolean result. Used for
 * ldap.login, ldap.exists, ldap.is_member. The builtin shape:
 *   bi::Decl <<
 *     (bi::ArgSeq << arg0 << arg1 << ... ) <<
 *     (bi::Result << name << type)
 */
static Node string_arg(const char *name)
{
	return bi::Arg << (bi::Name ^ name)
	               << bi::Description
	               << (bi::Type << bi::String);
}

static Node bool_result_decl(std::initializer_list<const char *> arg_names)
{
	Node argseq = bi::ArgSeq;
	for(const char *n : arg_names){
		argseq << string_arg(n);
	}
	return bi::Decl
		<< argseq
		<< (bi::Result
			<< (bi::Name ^ "result")
			<< bi::Description
			<< (bi::Type << bi::Boolean));
}

static Node string_result_decl(std::initializer_list<const char *> arg_names)
{
	Node argseq = bi::ArgSeq;
	for(const char *n : arg_names){
		argseq << string_arg(n);
	}
	return bi::Decl
		<< argseq
		<< (bi::Result
			<< (bi::Name ^ "result")
			<< (bi::Description ^ "JSON-encoded search result")
			<< (bi::Type << bi::String));
}


/* Build a no-arg decl returning a string result. Used for ocsp.check(). */
static Node nullary_string_result_decl(const char *result_desc)
{
	return bi::Decl
		<< bi::ArgSeq
		<< (bi::Result
			<< (bi::Name ^ "result")
			<< (bi::Description ^ result_desc)
			<< (bi::Type << bi::String));
}


static void register_host_builtins(Interpreter& interp)
{
	auto& builtins = *interp.builtins();

	/* LDAP — passwordless directory access. */
	builtins.register_builtin(BuiltInDef::create(
			Location("ldap.search"),
			string_result_decl({"url", "bind_dn", "bind_pw",
			                    "base_dn", "scope", "filter", "attrs"}),
			&builtin_ldap_search));

	builtins.register_builtin(BuiltInDef::create(
			Location("ldap.exists"),
			bool_result_decl({"url", "bind_dn", "bind_pw", "base_dn", "filter"}),
			&builtin_ldap_exists));

	builtins.register_builtin(BuiltInDef::create(
			Location("ldap.is_member"),
			bool_result_decl({"url", "bind_dn", "bind_pw", "group_dn", "user_dn"}),
			&builtin_ldap_is_member));

	/* OCSP — revocation check over the current connection's verified
	 * chain. Returns a JSON string of per-cert statuses; policy decides
	 * what combination is "allow". */
	builtins.register_builtin(BuiltInDef::create(
			Location("ocsp.check"),
			nullary_string_result_decl("JSON array of per-cert OCSP status"),
			&builtin_ocsp_check));

	/* CRL — same shape as ocsp.check but against CRLs fetched from
	 * the cert's crlDistributionPoints extension (cached in memory). */
	builtins.register_builtin(BuiltInDef::create(
			Location("crl.check"),
			nullary_string_result_decl("JSON array of per-cert CRL status"),
			&builtin_crl_check));

	/* audit.log — DEBUG-level audit note from the policy. Returns bool so
	 * it composes inside rule bodies. */
	builtins.register_builtin(BuiltInDef::create(
			Location("audit.log"),
			bool_result_decl({"message"}),
			&builtin_audit_log));
}

} /* anonymous namespace */


/* ---- The C façade --------------------------------------------------- */

struct rego_engine {
	std::unique_ptr<Interpreter> interp;
};


extern "C" struct rego_engine *rego_engine_new(
		struct ca_plugin *plg,
		const char *policy_file)
{
	if(!plg || !policy_file){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: rego_engine_new: null plugin or policy_file");
		return nullptr;
	}

	g_plugin = plg;

	auto *e = new rego_engine();
	try{
		e->interp = std::make_unique<Interpreter>();
		register_host_builtins(*e->interp);
		Node result = e->interp->add_module_file(policy_file);
		if(result && result->type() == Error){
			mosquitto_log_printf(MOSQ_LOG_ERR,
					"cert-rego: failed to load rego policy %s: %s",
					policy_file, rego::to_key(result).c_str());
			delete e;
			return nullptr;
		}
	}catch(const std::exception& ex){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: exception while initialising rego engine: %s",
				ex.what());
		delete e;
		return nullptr;
	}catch(...){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: unknown exception while initialising rego engine");
		delete e;
		return nullptr;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO,
			"cert-rego: rego policy loaded from %s", policy_file);
	return e;
}


extern "C" int rego_engine_reload(struct rego_engine *e, const char *policy_file)
{
	if(!e || !policy_file) return -1;

	try{
		auto fresh = std::make_unique<Interpreter>();
		register_host_builtins(*fresh);
		Node result = fresh->add_module_file(policy_file);
		if(result && result->type() == Error){
			mosquitto_log_printf(MOSQ_LOG_ERR,
					"cert-rego: policy reload failed, keeping previous policy: %s",
					rego::to_key(result).c_str());
			return -1;
		}
		e->interp = std::move(fresh);
	}catch(const std::exception& ex){
		mosquitto_log_printf(MOSQ_LOG_ERR,
				"cert-rego: exception during policy reload: %s — keeping previous",
				ex.what());
		return -1;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO,
			"cert-rego: rego policy reloaded from %s", policy_file);
	if(g_plugin && g_plugin->audit){
		char extras[512];
		char *esc = audit_log_escape_json_string(policy_file);
		if(esc){
			snprintf(extras, sizeof(extras), "\"policy\":%s", esc);
			audit_log_event(g_plugin->audit, "policy.reload", "ok", extras);
			mosquitto_free(esc);
		}
	}
	return 0;
}


extern "C" int rego_engine_eval_bool(
		struct rego_engine *e,
		const char *entrypoint,
		const char *input_json,
		bool *allow_out)
{
	if(!e || !entrypoint || !allow_out) return -1;
	*allow_out = false;

	try{
		if(input_json){
			Node err_node = e->interp->set_input_json(input_json);
			if(err_node && err_node->type() == Error){
				mosquitto_log_printf(MOSQ_LOG_WARNING,
						"cert-rego: set_input_json failed: %s",
						rego::to_key(err_node).c_str());
				return -1;
			}
		}

		rego::Output out = e->interp->query_output(entrypoint);
		if(!out.ok()){
			auto errs = out.errors();
			for(const auto& err : errs){
				mosquitto_log_printf(MOSQ_LOG_WARNING,
						"cert-rego: rego eval error: %s", err.c_str());
			}
			return -1;
		}

		if(out.size() == 0){
			/* Undefined result — fail closed. */
			return 0;
		}

		Node expressions = out.expressions();
		if(!expressions || expressions->empty()){
			return 0;
		}

		Node last = expressions->back();
		auto maybe_bool = rego::try_get_bool(last);
		if(maybe_bool.has_value()){
			*allow_out = maybe_bool.value();
		}else{
			/* Non-boolean result — treat as false under fail-closed. */
			*allow_out = false;
		}
		return 0;
	}catch(const std::exception& ex){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: exception during rego eval: %s", ex.what());
		return -1;
	}catch(...){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"cert-rego: unknown exception during rego eval");
		return -1;
	}
}


extern "C" int rego_engine_eval_bool_with_chain(
		struct rego_engine *e,
		const char *entrypoint,
		const char *input_json,
		void *chain,
		bool *allow_out)
{
	/* Narrow dynamic scope: the chain is visible to ocsp.check() for the
	 * duration of this eval only. An exception in the Rego engine still
	 * goes through the catch below so the stash is cleared before the
	 * error is returned. */
	g_current_chain = static_cast<STACK_OF(X509) *>(chain);
	int rc;
	try{
		rc = rego_engine_eval_bool(e, entrypoint, input_json, allow_out);
	}catch(...){
		g_current_chain = nullptr;
		throw;
	}
	g_current_chain = nullptr;
	return rc;
}


extern "C" void rego_engine_drop(struct rego_engine *e)
{
	if(!e) return;
	delete e;
}
