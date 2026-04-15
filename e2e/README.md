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
| `reload_broken_policy_keeps_previous` | SIGHUP with a syntactically broken policy file leaves the broker up and serving under the old policy. |
