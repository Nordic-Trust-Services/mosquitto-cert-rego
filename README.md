# mosquitto_cert_rego

External Eclipse Mosquitto plugin that authenticates MQTT clients by their X.509 certificate and asks a [Rego](https://www.openpolicyagent.org/docs/policy-language) policy whether to allow the connection (and each subsequent publish/subscribe). Drop-in `.so` against stock mosquitto 2.0+ — no broker patches.

- **Passwordless.** The cert is the credential. MQTT CONNECT passwords are never forwarded.
- **Multi-root CAs.** One trust store can span many roots; policies dispatch on which root the chain anchored to.
- **Rego is authoritative.** Chain-verify failures are surfaced to the policy, not auto-denied — you decide whether an expired intermediate during a root rotation is acceptable.
- **External-service host functions.** `ldap.search/exists/is_member`, `ocsp.check`, `crl.check`, `audit.log`, plus rego-cpp's built-in `http.send` for OAuth2 / OIDC introspection.
- **Structured audit.** JSON-lines with cert identity on every decision; file + syslog sinks; per-line truncation; level filter (deny-only in production, full DEBUG when chasing something).
- **SIGHUP hot reload** with atomic swap; broken policies leave the previous one running.
- **Native C++ via [rego-cpp](https://github.com/microsoft/rego-cpp).** No sidecar, no WASM runtime, no Rust.

## Quickstart

Install runtime deps (Debian / Ubuntu):

```bash
sudo apt install libssl-dev libcjson-dev libmosquitto-dev libldap2-dev cmake build-essential git
```

Build [rego-cpp](https://github.com/microsoft/rego-cpp) with `-DCMAKE_POSITION_INDEPENDENT_CODE=ON` (see [ARCHITECTURE.md](ARCHITECTURE.md#building-rego-cpp) for the exact flags), then build the plugin:

```bash
cmake -B build -S . -DREGOCPP_ROOT=/opt/regocpp
cmake --build build -j$(nproc)
```

Wire it up in `mosquitto.conf`:

```
listener 8883
cafile /etc/mosquitto/ca/bundle.pem
certfile /etc/mosquitto/server.crt
keyfile /etc/mosquitto/server.key
require_certificate true
use_identity_as_username false

plugin /usr/local/lib/mosquitto/mosquitto_cert_rego.so
plugin_opt_cert_rego_ca_file     /etc/mosquitto/ca/bundle.pem
plugin_opt_cert_rego_policy_file /etc/mosquitto/policies/access.rego
plugin_opt_cert_rego_audit_log_file /var/log/mosquitto/cert-rego-audit.log
```

Smallest useful policy — CN-scoped topic namespace:

```rego
package mqtt

default connect := false
default acl := false

connect {
    input.cert.chain_ok
    input.cert.cn != ""
}

acl {
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}
```

Reload the policy without dropping connections: `kill -HUP $(pidof mosquitto)`.

## Examples

Eight progressively richer policies under [examples/](examples/):

1. [`01_minimal_allow_all.rego`](examples/01_minimal_allow_all.rego) — smoke-test baseline
2. [`02_cn_topic_scope.rego`](examples/02_cn_topic_scope.rego) — CN-scoped topics + chain-validity-window
3. [`03_ldap_group_gate.rego`](examples/03_ldap_group_gate.rego) — gated on LDAP group membership
4. [`04_multi_root_ca.rego`](examples/04_multi_root_ca.rego) — trust-anchor dispatch + per-anchor intermediate whitelist
5. [`05_ocsp_in_rego.rego`](examples/05_ocsp_in_rego.rego) — OCSP revocation expressed in Rego
6. [`06_custom_oid.rego`](examples/06_custom_oid.rego) — matching on custom certificate OIDs
7. [`07_crl_in_rego.rego`](examples/07_crl_in_rego.rego) — CRL revocation, optionally combined with OCSP
8. [`08_chain_traversal.rego`](examples/08_chain_traversal.rego) — overriding specific chain-verification failures
9. [`09_degraded_scope_on_expired.rego`](examples/09_degraded_scope_on_expired.rego) — graceful degradation on an expired chain
10. [`10_san_uri_roles.rego`](examples/10_san_uri_roles.rego) — role-based access from `urn:` SAN URIs (admin / fleet / reader)
11. [`11_rbac_matrix.rego`](examples/11_rbac_matrix.rego) — full RBAC matrix: four roles × five topic namespaces, action-level differentiation, explicit negative cases annotated inline

## Testing

- **Unit smoke**: `cd build && ctest --output-on-failure`
- **End-to-end + cybersec battery** (real broker, real PKI, OCSP/CRL responders, fuzz, sanitizers): see [e2e/README.md](e2e/README.md).

## Documentation

- [README.md](README.md) — this file
- [ARCHITECTURE.md](ARCHITECTURE.md) — flow, build details, full configuration table, Rego input doc, host functions, fail-closed semantics, logging, limitations
- [examples/](examples/) — annotated Rego policies
- [e2e/README.md](e2e/README.md) — end-to-end test harness and cybersec suite
- [test.conf](test.conf) — annotated mosquitto config with every plugin option
- [CONTRIBUTING.md](CONTRIBUTING.md) — patches welcome

## License

EPL-2.0 OR BSD-3-Clause, matching upstream mosquitto's first-class plugins.
