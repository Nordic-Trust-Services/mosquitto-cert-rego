/*
 * Standalone test harness for rego_engine. No mosquitto broker, no real
 * LDAP server, no real PKI — synthesises JSON input documents and asserts
 * that the eval path returns the expected bool.
 *
 * Usage:
 *   test_rego_engine <simple_policy.rego> [multi_root_policy.rego]
 *
 * With one argument: runs the simple-policy smoke tests only.
 * With two arguments: also runs the multi-root trust-anchor dispatch tests.
 *
 * Exit 0 with "TESTS OK" means the rego-cpp integration, the input-doc
 * shape, and the trust-anchor routing are all behaving as the plugin
 * will use them in production.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
#include "cert_auth.h"
#include "rego_engine.h"
}

static int g_failed = 0;

#define CHECK(cond, msg) do { \
	if(!(cond)){ \
		std::fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
		g_failed++; \
	}else{ \
		std::fprintf(stderr, "ok: %s\n", msg); \
	} \
} while(0)


/* Build a passwordless connect input doc. Caller chooses cn and the trust
 * anchor fingerprint; everything else is stable filler. The event field
 * is intentionally omitted — each entrypoint (data.mqtt.connect vs
 * data.mqtt.acl) already disambiguates. */
static std::string connect_input(const char *cn, const char *anchor_fp)
{
	std::string chain_json =
		anchor_fp
		? std::string("["
			"{\"depth\":0,\"subject_dn\":\"CN=")+cn+"\",\"issuer_dn\":\"CN=test intermediate\","
			"\"serial\":\"deadbeef\",\"fingerprint_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\","
			"\"not_before_unix\":1700000000,\"not_after_unix\":1800000000,"
			"\"verify_ok\":true,\"errors\":[]},"
			"{\"depth\":1,\"subject_dn\":\"CN=test anchor\",\"issuer_dn\":\"CN=test anchor\","
			"\"serial\":\"01\",\"fingerprint_sha256\":\""+anchor_fp+"\","
			"\"not_before_unix\":1600000000,\"not_after_unix\":1900000000,"
			"\"verify_ok\":true,\"errors\":[]}]"
		: "[]";

	std::string s =
		"{"
		"\"now_unix_ms\":1713456789012,"
		"\"client\":{\"id\":\"test-client\",\"address\":\"127.0.0.1\",\"protocol_version\":5},"
		"\"cert\":{"
			"\"subject_dn\":\"CN="+std::string(cn)+",O=Test,C=US\","
			"\"cn\":\""+std::string(cn)+"\","
			"\"issuer_dn\":\"CN=Test CA\","
			"\"serial\":\"deadbeef\","
			"\"not_before_unix\":1700000000,"
			"\"not_after_unix\":1800000000,"
			"\"fingerprint_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\","
			"\"san\":{\"dns\":[],\"email\":[],\"uri\":[]},"
			"\"trust_anchor\":"+(anchor_fp
				? "{\"subject_dn\":\"CN=test anchor\",\"fingerprint_sha256\":\""+std::string(anchor_fp)+"\"}"
				: "null")+","
			"\"chain_ok\":true,"
			"\"chain_errors\":[],"
			"\"chain\":"+chain_json+
		"},"
		"\"connect\":{\"username\":\""+std::string(cn)+"\"}"
		"}";
	return s;
}


static std::string acl_input(const char *cn, const char *topic,
		const char *action, const char *anchor_fp)
{
	std::string chain_json =
		anchor_fp
		? std::string("["
			"{\"depth\":0,\"subject_dn\":\"CN=")+cn+"\",\"issuer_dn\":\"CN=test intermediate\","
			"\"serial\":\"deadbeef\",\"fingerprint_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\","
			"\"not_before_unix\":1700000000,\"not_after_unix\":1800000000,"
			"\"verify_ok\":true,\"errors\":[]}]"
		: "[]";

	std::string s =
		"{"
		"\"now_unix_ms\":1713456789012,"
		"\"client\":{\"id\":\"test-client\",\"address\":\"127.0.0.1\",\"protocol_version\":5},"
		"\"cert\":{"
			"\"subject_dn\":\"CN="+std::string(cn)+"\","
			"\"cn\":\""+std::string(cn)+"\","
			"\"issuer_dn\":\"CN=Test CA\","
			"\"serial\":\"deadbeef\","
			"\"not_before_unix\":1700000000,"
			"\"not_after_unix\":1800000000,"
			"\"fingerprint_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\","
			"\"san\":{\"dns\":[],\"email\":[],\"uri\":[]},"
			"\"trust_anchor\":"+(anchor_fp
				? "{\"subject_dn\":\"CN=test anchor\",\"fingerprint_sha256\":\""+std::string(anchor_fp)+"\"}"
				: "null")+","
			"\"chain_ok\":true,"
			"\"chain_errors\":[],"
			"\"chain\":"+chain_json+
		"},"
		"\"acl\":{"
			"\"action\":\""+std::string(action)+"\","
			"\"topic\":\""+std::string(topic)+"\","
			"\"qos\":1,\"retain\":false"
		"}"
		"}";
	return s;
}


/* ---- simple-policy tests --------------------------------------------- */

static void run_simple_tests(struct ca_plugin &plg, const char *policy_path)
{
	struct rego_engine *rego = rego_engine_new(&plg, policy_path);
	CHECK(rego != nullptr, "simple policy: engine loaded");
	if(!rego) return;

	/* Basic connect allow/deny by CN. */
	{
		auto in = connect_input("alice", nullptr);
		bool allow = false;
		int rc = rego_engine_eval_bool(rego, "data.mqtt.connect", in.c_str(), &allow);
		CHECK(rc == 0, "simple: connect_allow(alice) rc==0");
		CHECK(allow, "simple: connect_allow(alice) == true");
	}
	{
		auto in = connect_input("bob", nullptr);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.connect", in.c_str(), &allow);
		CHECK(!allow, "simple: connect_allow(bob) == false");
	}

	/* ACL scoped by CN. */
	{
		auto in = acl_input("alice", "devices/alice/status", "write", nullptr);
		bool allow = false;
		int rc = rego_engine_eval_bool(rego, "data.mqtt.acl", in.c_str(), &allow);
		CHECK(rc == 0, "simple: acl(alice, own topic) rc==0");
		CHECK(allow, "simple: acl(alice, devices/alice/..) == true");
	}
	{
		auto in = acl_input("alice", "devices/bob/status", "write", nullptr);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.acl", in.c_str(), &allow);
		CHECK(!allow, "simple: acl(alice, devices/bob/..) == false");
	}

	/* Reload keeps serving. */
	{
		int rc = rego_engine_reload(rego, policy_path);
		CHECK(rc == 0, "simple: reload succeeds");
	}
	{
		auto in = connect_input("alice", nullptr);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.connect", in.c_str(), &allow);
		CHECK(allow, "simple: post-reload connect_allow(alice)");
	}

	rego_engine_drop(rego);
}


/* ---- multi-root tests ------------------------------------------------ */

/* Fingerprints defined in tests/test_policy_multi_root.rego. */
static const char *OPERATOR_FP =
	"aaaa000000000000000000000000000000000000000000000000000000000000";
static const char *DEVICE_FP =
	"bbbb000000000000000000000000000000000000000000000000000000000000";
static const char *UNKNOWN_FP =
	"ffff000000000000000000000000000000000000000000000000000000000000";

static void run_multi_root_tests(struct ca_plugin &plg, const char *policy_path)
{
	struct rego_engine *rego = rego_engine_new(&plg, policy_path);
	CHECK(rego != nullptr, "multi-root: engine loaded");
	if(!rego) return;

	/* Operator cert: any non-empty CN should connect. */
	{
		auto in = connect_input("alice", OPERATOR_FP);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.connect", in.c_str(), &allow);
		CHECK(allow, "multi-root: operator-anchored alice connects");
	}

	/* Device cert: any non-empty CN should also connect. */
	{
		auto in = connect_input("device-01", DEVICE_FP);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.connect", in.c_str(), &allow);
		CHECK(allow, "multi-root: device-anchored device-01 connects");
	}

	/* Unknown trust anchor: must not connect. */
	{
		auto in = connect_input("alice", UNKNOWN_FP);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.connect", in.c_str(), &allow);
		CHECK(!allow, "multi-root: unknown anchor is rejected");
	}

	/* Missing trust anchor (defensive): must not connect. */
	{
		auto in = connect_input("alice", nullptr);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.connect", in.c_str(), &allow);
		CHECK(!allow, "multi-root: null anchor is rejected");
	}

	/* Operator: broad access under devices/. */
	{
		auto in = acl_input("alice", "devices/other/cmd", "write", OPERATOR_FP);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.acl", in.c_str(), &allow);
		CHECK(allow, "multi-root: operator may write cross-device topics");
	}

	/* Device: scoped to own subtree only. */
	{
		auto in = acl_input("device-01", "devices/device-01/telemetry",
		                    "write", DEVICE_FP);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.acl", in.c_str(), &allow);
		CHECK(allow, "multi-root: device may write own subtree");
	}
	{
		auto in = acl_input("device-01", "devices/device-02/telemetry",
		                    "write", DEVICE_FP);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.acl", in.c_str(), &allow);
		CHECK(!allow, "multi-root: device cannot write other device's subtree");
	}

	/* Identity confusion: operator CN presented with device anchor shouldn't
	 * get operator privileges — the policy routes on anchor, not CN. */
	{
		auto in = acl_input("alice", "devices/alice/foo", "write", DEVICE_FP);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.acl", in.c_str(), &allow);
		CHECK(allow,
			"multi-root: device-anchored alice writes own subtree");
	}
	{
		auto in = acl_input("alice", "devices/bob/foo", "write", DEVICE_FP);
		bool allow = false;
		rego_engine_eval_bool(rego, "data.mqtt.acl", in.c_str(), &allow);
		CHECK(!allow,
			"multi-root: device-anchored alice cannot cross into bob's subtree");
	}

	rego_engine_drop(rego);
}


int main(int argc, char **argv)
{
	if(argc < 2){
		std::fprintf(stderr,
				"usage: %s <simple.rego> [multi_root.rego]\n", argv[0]);
		return 2;
	}

	struct ca_plugin plg;
	std::memset(&plg, 0, sizeof(plg));
	plg.cfg.ldap.require_tls = true;
	plg.cfg.ldap.connect_timeout_ms = 3000;
	plg.cfg.ldap.op_timeout_ms = 5000;

	std::fprintf(stderr, "== simple policy tests ==\n");
	run_simple_tests(plg, argv[1]);

	if(argc >= 3){
		std::fprintf(stderr, "\n== multi-root policy tests ==\n");
		run_multi_root_tests(plg, argv[2]);
	}

	if(g_failed > 0){
		std::fprintf(stderr, "\nTESTS FAILED: %d check(s) failed\n", g_failed);
		return 1;
	}
	std::fprintf(stderr, "\nTESTS OK\n");
	return 0;
}
