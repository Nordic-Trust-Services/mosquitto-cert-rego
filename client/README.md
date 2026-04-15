# cert_rego_client — reference Python client

A small Python CLI that exercises the [mosquitto cert-rego plugin](../README.md) end to end. Present a client certificate and connect / publish / subscribe — the plugin is passwordless, so the client's only authentication factor is its X.509 cert. Exit codes map cleanly to the plugin's decisions so the client is usable from shell scripts and CI.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Generate a test PKI

`gen_test_certs.sh` produces a root CA, one intermediate CA, a server cert for the broker, and two client certs (`alice` and `bob`) in a fresh `pki/` directory. It is deliberately small and reproducible.

```bash
./gen_test_certs.sh pki
# or pick a different hostname baked into the server cert's SAN:
SERVER_HOST=broker.internal ./gen_test_certs.sh pki
```

Files produced:

| File | Used by |
|---|---|
| `pki/bundle.pem` | `cafile` in mosquitto.conf AND `plugin_opt_cert_rego_ca_file` |
| `pki/server.crt`, `pki/server.key` | `certfile` / `keyfile` in mosquitto.conf |
| `pki/alice.crt`, `pki/alice.key` | good client, CN=alice |
| `pki/bob.crt`, `pki/bob.key` | unauthorised client (for deny tests) |
| `pki/root.crt`, `pki/intermediate.crt` | separate CA pieces if you want them |

The intermediate gives you a 2-deep chain to verify that the plugin actually walks intermediates rather than stopping at the leaf.

## A minimal broker config that exercises this

Using example policy `02_cn_topic_scope.rego` from `../examples/`, which allows any cert with a CN and scopes topics by CN:

```
# mosquitto.conf
per_listener_settings true

listener 8883
cafile   /path/to/pki/bundle.pem
certfile /path/to/pki/server.crt
keyfile  /path/to/pki/server.key
require_certificate true

plugin /usr/local/lib/mosquitto/mosquitto_cert_rego.so
plugin_opt_cert_rego_ca_file           /path/to/pki/bundle.pem
plugin_opt_cert_rego_policy_file  /path/to/examples/02_cn_topic_scope.rego
```

## Using the client

### Just connect (auth smoke test)

```bash
./cert_rego_client.py --host broker --port 8883 \
    --ca pki/bundle.pem \
    --cert pki/alice.crt --key pki/alice.key \
    connect
```

Exit `0` means the broker accepted `alice`. Exit `1` means the Rego policy denied the connection — which is what you'd expect if you ran the same command with `pki/bob.crt`/`pki/bob.key` against a policy that only admits alice.

### Publish one message

```bash
./cert_rego_client.py --host broker --port 8883 \
    --ca pki/bundle.pem \
    --cert pki/alice.crt --key pki/alice.key \
    publish --topic 'devices/alice/status' --message '{"online": true}'
```

With the CN-topic-scope policy, the publish succeeds because `alice` owns the `devices/alice/*` subtree. Publishing to `devices/bob/*` as alice exits `1` (ACL denied).

### Subscribe

```bash
./cert_rego_client.py --host broker --port 8883 \
    --ca pki/bundle.pem \
    --cert pki/alice.crt --key pki/alice.key \
    -v subscribe --topic 'devices/alice/#' --timeout 10
```

Prints every message received to stdout, one per line, as `topic payload`. Exits after 10 seconds, or on Ctrl-C if `--timeout 0`.

### Multi-root PKI

To exercise the `04_multi_root_ca.rego` policy, generate a two-root PKI:

```bash
MULTI_ROOT=1 ./gen_test_certs.sh pki
```

Produces `bundle_a.pem` (operator root) and `bundle_b.pem` (device root) plus client certs under each. Pass both to the plugin:

```
plugin_opt_cert_rego_ca_file /path/to/pki/bundle_a.pem,/path/to/pki/bundle_b.pem
```

Then connect under either anchor and the policy will route on `input.cert.trust_anchor.fingerprint_sha256`:

```bash
# Operator identity
./cert_rego_client.py --host broker --port 8883 \
    --ca pki/bundle_all.pem \
    --cert pki/operator_alice.crt --key pki/operator_alice.key \
    connect

# Device identity
./cert_rego_client.py --host broker --port 8883 \
    --ca pki/bundle_all.pem \
    --cert pki/device_01.crt --key pki/device_01.key \
    connect
```

Paste the fingerprints that `gen_test_certs.sh` prints into the `root_a_fp` / `root_b_fp` constants in `examples/04_multi_root_ca.rego` so the policy matches your PKI.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | auth denied — Rego said no, OCSP revoked, or ACL refused |
| 2 | TLS handshake failed — broker cert not trusted by `--ca`, or client cert rejected at the TLS layer before the plugin saw it |
| 3 | network / timeout / unreachable |
| 4 | configuration error — missing file, bad arg |
| 5 | unexpected MQTT protocol or library error |

Code `1` collapses every plugin-originated denial (basic auth, OCSP, ACL) into a single shell-friendly signal. If you need to distinguish them, run with `-v` and parse the `DISCONNECT reason_code=` line.

## Troubleshooting

### Why exit 2 instead of 1?

The TLS handshake fails **before** the plugin gets to run. Either:
- The broker's server cert isn't signed by your `--ca`, or
- `require_certificate true` is set on the listener and your client cert isn't signed by the broker's `cafile`, or
- The server hostname doesn't match the cert's CN/SAN. Pass `--insecure` to suppress this check temporarily.

Always rule out TLS problems first — the cert-rego plugin's policy is only reachable once the TLS layer accepts the client.

### CONNECT succeeds but subscribe/publish is denied

The Rego connect rule passed but the ACL rule rejected the operation. Rerun with `-vv` to see the DISCONNECT / SUBACK / PUBACK reason codes, then check the broker's audit log (`plugin_opt_cert_rego_audit_log_file`) — each ACL denial is recorded with the topic and action.

### Policy calls `ldap.search` / `ldap.is_member` but the policy evaluates to false

The plugin is passwordless, but LDAP host functions still need service-account credentials to bind to the directory. Those live in the policy (where they can be pulled in from a `data.json`) and in the plugin's `plugin_opt_cert_rego_ldap_*` options — not in anything the client sends. Check:
1. `plugin_opt_cert_rego_ldap_allowed_urls` lists the LDAP URL your policy passes to `ldap.search`.
2. `plugin_opt_cert_rego_ldap_require_tls` is consistent with the URL scheme (default `true` rejects `ldap://`).
3. The audit log (`plugin_opt_cert_rego_audit_log_file`) shows the `ldap` events — it records URL, result code, entry count, and whether the response came from cache. A rejected URL surfaces as `rc: url_not_allowed`.

## License

EPL-2.0 OR BSD-3-Clause, matching the rest of the plugin.
