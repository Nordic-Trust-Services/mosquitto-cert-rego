# e2e test harness

Drives a real mosquitto broker with the cert-rego plugin loaded and runs
a smoke + cybersec suite against it.

## Prerequisites

- `mosquitto` and `mosquitto_pub/_sub` built at `/home/hs/mosquitto/build`
  (apt's 2.0.11 lacks the v5 plugin ABI this plugin targets; build 2.1.2
  from the upstream source tree via `cmake -B build && cmake --build build`)
- The plugin compiled at `/tmp/cert-rego-build/mosquitto_cert_rego.so`
- Python 3.10+ with `cryptography` installed (for generating the
  negative-case expired cert)
- `openssl` (>=3.0)

## One-shot

```
./e2e/run-all.sh
```

Regenerates the PKI + negative certs on first run, starts the broker,
runs both suites, tears down. Exits non-zero on any failure.

## Individual parts

```
# PKI
MULTI_ROOT=1 ./client/gen_test_certs.sh e2e/pki
./e2e/gen-negative-certs.sh

# broker
./e2e/run-broker.sh              # background, PID in e2e/run/broker.pid
./e2e/run-broker.sh -f           # foreground, Ctrl-C to stop
./e2e/stop-broker.sh

# suites
./e2e/smoke.sh
./e2e/cybersec.py                # full suite
./e2e/cybersec.py acl_cross_device_deny     # single test by name
```

Artefacts land under `e2e/run/` — `mosquitto.conf` (stamped with real
paths), `policy.rego` (with fingerprints substituted), `broker.log`,
`broker.stdout`, and the plugin's `audit.jsonl`.

## What the cybersec suite covers

| Test | What it asserts |
|---|---|
| `auth_untrusted_root_tls_reject` | Client cert under a CA not in `bundle_all.pem` is rejected at the TLS handshake; plugin never sees it. |
| `auth_expired_leaf_tls_reject` | An expired leaf is rejected by the TLS layer before the plugin. |
| `acl_cross_device_deny` | `device_01` publishing into `devices/device-02/*` is denied and the deny line identifies the cert. |
| `acl_fleet_wildcard_from_device_deny` | A device trying to subscribe to `devices/+/secret` (wildcard escape of its own subtree) is denied. |
| `audit_framing_cn_injection` | A CN containing `"`, `\\`, newline does not break audit JSON framing; every emitted line still parses. |
| `audit_decision_id_correlates_connect_and_acl` | `decision_id` is positive, monotonic, and unique across connect + ACL events within one client session. |
| `audit_line_truncation_kicks_in` | Every audit line stays within the configured line cap (8 KB in e2e). |
| `audit_deny_carries_full_metadata` | An ACL deny line carries the same cert identity fields an allow line does — CN, DNs, serial, fingerprint, trust anchor FP, chain_ok, chain_errors, decision_id, client_id, remote_addr. |
| `policy_note_at_debug_only` | The Rego `audit.log(message)` host function emits a `policy.note` event at DEBUG with the message body. |
| `reload_race_under_load_atomic_swap` | Alternating-policy SIGHUP every 150 ms for 3 s while 4 client threads hammer connect+publish: broker survives, audit stays parseable, `decision_id`s remain unique, both policy tags observed, post-race connect still works. |
| `fuzz_cert_inputs_keep_audit_intact` | Property-based: 30 randomised certs (varying CN, OU stack depth, SAN dns/email/uri counts, custom OID extensions with random byte payloads). Asserts broker stays alive, every audit line parses as JSON, required fields present, `cn` round-trips exactly or via the `\u2026` truncation marker, and `decision_id` stays monotonic and unique. Fixed RNG seed so failures reproduce. |
| `ocsp_good_cert_allowed` | Cert with `status:good` from a live OCSP responder is allowed by an `ocsp.check()`-gated policy. |
| `ocsp_revoked_cert_denied` | Cert revoked at the responder is denied by the same policy. |
| `ocsp_responder_unreachable_fail_closed` | Same policy, responder down: `status:error` flows through Rego as deny — fail-closed. |
| `crl_good_cert_allowed` | Cert listed nowhere in the CRL gets `status:good` from the local HTTP-served CRL and is allowed by a `crl.check()`-gated policy. |
| `crl_revoked_cert_denied` | Cert whose serial appears in the CRL gets `status:revoked` and is denied. |
| `crl_fetcher_unreachable_fail_closed` | Same policy, CRL HTTP server down: `status:error` → deny. |
| `crl_url_scheme_allowlist_blocks_file_uri` | A cert whose `crlDistributionPoints` points at `file:///etc/passwd` does NOT cause the plugin to read the file — `http_fetch.c` only accepts http/https schemes; `crl.check()` returns `status:error err:fetch failed` → deny. |
| `acl_topic_dotdot_is_literal_segment` | Confirms broker + plugin do not normalise MQTT topics: `devices/device-01/../device-02/secret` is treated as a literal topic and round-trips byte-for-byte into the audit line. |
| `auth_empty_cn_cert_denied` | A cert with no CN (only OU + O) reaches the plugin; policy denies on `cn != ""`; audit records `cn=""`. |
| `auth_san_uri_role_based_rule` | Mints a cert with `X509v3 Subject Alternative Name: URI:urn:iotwidgits:role:admin`, installs a policy that grants admin-only access via `input.cert.san.uri` membership, verifies connect + publish succeed, and asserts the URN round-trips verbatim into the audit line's `san.uri` array. A second cert without the URN is denied by the same policy. |
| `fuzz_publish_payloads_keep_audit_intact` | 40 publishes from a legit operator cert with random topics (incl. unicode + injection bytes) and random payloads up to 4 KB. Asserts broker survives, audit lines stay parseable, every line within cap, ACL events carry structural fields. |
| `reconnect_storm_state_isolated` | 200 sequential connect→publish→disconnect cycles rotating across 4 client certs. Asserts broker stays alive, audit lines parse, decision_ids unique, every iteration produces a distinct connect (no session reuse leaking state). Especially valuable run under ASan via `run-asan.sh`. |
| `ocsp_malformed_response_fail_closed` | Adversarial Python responder returns garbage labelled `application/ocsp-response`; plugin must surface `status:error` and policy denies — does not crash. |
| `ocsp_truncated_response_fail_closed` | Same harness, body is one byte; plugin parses gracefully and denies. |
| `policy_returns_nonbool_fail_closed` | A policy where `data.mqtt.connect` resolves to a string (not a bool) must NOT be truthy-coerced — plugin denies. Verifies `rego_engine_eval_bool` only sets allow on exact boolean true. |

## Running under sanitizers

`./e2e/run-asan.sh` builds the plugin into `/tmp/cert-rego-build-asan/` with `-fsanitize=address,undefined`, restarts the broker with `LD_PRELOAD=libasan.so` and the sanitizer-built plugin, then runs the full cybersec suite. ASan reports go to `e2e/run/asan.log.<pid>`; the script fails the run if any `SUMMARY:` or runtime-error line appears.

`detect_leaks=0` because mosquitto's intentional one-shot allocations on shutdown would otherwise dominate the report; ASan's heap-buffer-overflow / use-after-free / stack-use-after-return / strict-string-checks coverage stays on. UBSan runs alongside with `halt_on_error=0`.
| `reload_broken_policy_keeps_previous` | SIGHUP with a syntactically broken policy file leaves the broker up and serving under the old policy. |
