# mosquitto_cert_rego

External Eclipse Mosquitto plugin that authenticates clients by X.509 certificate and delegates the allow/deny decision to a Rego policy, with LDAP (and OAuth2/HTTP via rego-cpp's `http.send`) available to the policy as host functions.

- **Passwordless.** Authentication is the client's certificate plus whatever the Rego policy asks of external services. MQTT CONNECT passwords are never forwarded.
- **Multi-root CAs.** The plugin trust store can span many roots; the Rego input doc exposes which root the chain anchored to, so policies can dispatch per-CA.
- **No broker patches.** Loads as a drop-in `.so` against stock upstream mosquitto 2.0+.
- **Rego policy as the decision engine.** Powered by native C++ [rego-cpp](https://github.com/microsoft/rego-cpp) — no sidecar, no WASM runtime, no Rust.
- **LDAP as Rego host functions.** `ldap.search`, `ldap.exists`, `ldap.is_member` are dispatched from Rego policies into libldap via custom built-ins registered at plugin load.
- **OCSP post-Rego.** Revocation checking is optional and runs only on connections the policy already allowed, so denied clients never cost an OCSP round-trip.
- **Structured JSON-lines audit log.**
- **SIGHUP hot reload** of the policy file via `MOSQ_EVT_RELOAD`.

## Architecture

```
                  TLS handshake
  client -----------------------> mosquitto broker
                                         |
                                         v
                                  MOSQ_EVT_BASIC_AUTH
                                         |
                                 cert_parse.c + ocsp_check.c::ca_verify_chain
                                         |
                                    input JSON
                          (leaf, trust_anchor, chain)
                                         |
                                         v
                                 rego_engine.cpp
                                 rego-cpp Interpreter
                                 ├── ldap.search       → ldap_query.c → libldap
                                 ├── ldap.exists       → ldap_query.c → libldap
                                 ├── ldap.is_member    → ldap_query.c → libldap
                                 ├── ocsp.check        → ocsp_check.c (walks current chain)
                                 └── http.send         → rego-cpp built-in
                                         |
                                    allow / deny
                                         |
                                         v
                             MOSQ_ERR_SUCCESS / AUTH
                                         |
                                 audit_log.c JSON lines
```

The only C++ translation unit is [`rego_engine.cpp`](rego_engine.cpp), which wraps rego-cpp's `Interpreter` and registers the three `ldap.*` builtins. Everything else is plain C.

The flow on connect:

1. **Chain build.** Plugin calls `X509_verify_cert` against the trust store (which may hold multiple roots, see [Configuration](#configuration)) with a verify callback in *collecting mode* — every per-cert error is recorded but never aborts the walk.
2. **Input doc.** Leaf fields + full chain (one object per cert, each with its own `verify_ok` + `errors[]`) + `chain_ok` summary + deduplicated `chain_errors[]` are packaged into a JSON doc. Policies that want the clean "chain verified" gate just check `input.cert.chain_ok`; policies that want to override specific failure modes (an expired intermediate during a root rotation, for example) iterate the per-cert errors.
3. **Rego eval.** `data.mqtt.connect` is called with the chain in scope for host functions. Policies consult cert fields, the verification results, LDAP, OCSP (`ocsp.check()`), CRL (`crl.check()`), arbitrary HTTP services (rego-cpp's `http.send`), or any combination.
4. **Result.** Policy's bool is the answer. The plugin does **not** pre-deny on chain-verify failure — Rego is fully authoritative.

The ACL callback follows the same shape, hitting `data.mqtt.acl` on every publish/subscribe. OCSP and CRL are available during ACL evals too if the policy wants them.

## Build requirements

- CMake ≥ 3.15
- A C11 **and C++20** compiler (the C++ bump is forced by rego-cpp's public headers, which use `std::span`)
- OpenSSL development headers (`libssl-dev` / `openssl-devel`)
- OpenLDAP client (`libldap2-dev` / `openldap-devel`)
- mosquitto development headers (`libmosquitto-dev`), any version with plugin v5 (mosquitto 2.0+)
- `libcjson-dev` — transitive dependency of `<mosquitto.h>`
- [rego-cpp](https://github.com/microsoft/rego-cpp), **built with `-DCMAKE_POSITION_INDEPENDENT_CODE=ON`** so its static libs can be linked into our `.so`

On Debian / Ubuntu:

```
sudo apt install libssl-dev libcjson-dev libmosquitto-dev libldap2-dev cmake build-essential git
```

## Building rego-cpp

rego-cpp is not packaged in most distros. Build it from source, install under a local prefix, and point the plugin build at that prefix.

```bash
git clone https://github.com/microsoft/rego-cpp.git
cd rego-cpp
cmake -B build -S . \
    -DCMAKE_INSTALL_PREFIX=/opt/regocpp \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DREGOCPP_BUILD_TESTS=OFF \
    -DREGOCPP_BUILD_TOOLS=OFF
cmake --build build -j$(nproc)
sudo cmake --install build
```

**Gotchas worth knowing:**

1. **PIC is mandatory.** Without `-DCMAKE_POSITION_INDEPENDENT_CODE=ON` the resulting `librego.a` has non-PIC relocations and cannot link into the plugin `.so`. The linker error is `relocation R_X86_64_TPOFF32 ... can not be used when making a shared object`. If you see this, you forgot the flag.
2. **Transitive headers may not install.** rego-cpp fetches Trieste and snmalloc via `FetchContent` but does not always install their headers alongside its own. If the plugin build fails with `trieste/ast.h: No such file or directory` after a successful rego-cpp install, copy the headers manually:
   ```bash
   sudo cp -r build/_deps/trieste-src/include/* /opt/regocpp/include/
   sudo cp -r build/_deps/trieste-build/include/* /opt/regocpp/include/
   sudo cp -r build/_deps/snmalloc-src/src/snmalloc /opt/regocpp/include/
   ```
   Upstream may fix this — check the rego-cpp install tree first before copying.
3. **Debug vs Release.** Build in Release mode for production. Debug builds of rego-cpp are substantially slower and the plugin's policy eval happens per connect.

## Building the plugin

```bash
cmake -B build -S . -DREGOCPP_ROOT=/opt/regocpp
cmake --build build -j$(nproc)
sudo cmake --install build
```

Produces `${CMAKE_INSTALL_LIBDIR}/mosquitto/mosquitto_cert_rego.so` and installs the example policies under `${CMAKE_INSTALL_DOCDIR}/policies`.

## Running the test harness

A small C++ test binary exercises the rego eval path against a trivial policy. It runs without a live mosquitto broker and without a real LDAP server.

```bash
cd build
ctest --output-on-failure
```

Expected output: `TESTS OK`. The harness runs two policies: a simple CN-based policy (6 assertions — policy load, connect allow/deny, ACL allow/deny, reload, post-reload eval) and a multi-root trust-anchor dispatch policy (9 assertions — operator and device anchors allowed, unknown and null anchors rejected, per-anchor ACL rules, cross-device crossover blocked, identity confusion blocked).

## Configuration

See [`test.conf`](test.conf) for an annotated example. Plugin options are all `plugin_opt_cert_rego_*`:

| Option | Default | Meaning |
|---|---|---|
| `cert_rego_ca_file` | required unless `ca_path` set | **Comma-separated** list of PEM bundles. All loaded into one trust store; the policy can route on which root validated via `input.cert.trust_anchor`. |
| `cert_rego_ca_path` | required unless `ca_file` set | Hashed CA directory loaded alongside `ca_file` |
| `cert_rego_policy_file` | **required** | Path to `.rego` policy, reloaded on SIGHUP |
| `cert_rego_connect_entrypoint` | `data.mqtt.connect` | Rule name evaluated on CONNECT |
| `cert_rego_acl_entrypoint` | `data.mqtt.acl` | Rule name evaluated on ACL check |
| `cert_rego_ldap_allowed_urls` | empty | Comma-separated whitelist. Empty = plugin runs without LDAP support |
| `cert_rego_ldap_require_tls` | `true` | Reject `ldap://` URLs in the whitelist |
| `cert_rego_ldap_ca_file` | system default | CA bundle for LDAPS verification |
| `cert_rego_ldap_connect_timeout_ms` | `3000` | libldap `LDAP_OPT_NETWORK_TIMEOUT` |
| `cert_rego_ldap_op_timeout_ms` | `5000` | libldap `LDAP_OPT_TIMEOUT` |
| `cert_rego_ldap_cache_ttl` | `60` | Seconds to cache `ldap.search`/`exists`/`is_member`. `0` disables |
| `cert_rego_audit_log_file` | unset (disabled) | Path to JSON-lines audit log |
| `cert_rego_audit_log_fsync` | `false` | `fsync` on every line. Durable, slow |
| `cert_rego_audit_syslog_enabled` | `false` | Mirror every audit line to syslog (in addition to / instead of file) |
| `cert_rego_audit_syslog_ident` | `mosquitto-cert-rego` | Syslog program tag (`openlog(3)` ident) |
| `cert_rego_audit_syslog_facility` | `authpriv` | One of `auth`, `authpriv`, `daemon`, `user`, `local0..local7` |
| `cert_rego_audit_level` | `info` | Threshold filter: `error`, `warn`, `notice`, `info`, `debug` |
| `cert_rego_audit_line_cap` | `4096` | Hard per-line byte cap; over-long lines get rebuilt with `"truncated":true` (clamp 1024..16384) |
| `cert_rego_audit_chain_detail` | `false` | DEBUG: include the per-cert chain dump |
| `cert_rego_audit_chain_max_depth` | `8` | DEBUG: truncate chain dump to N entries |
| `cert_rego_audit_san` | `false` | DEBUG: include SAN sub-object |
| `cert_rego_audit_custom_oids` | `false` | DEBUG: include custom-extensions sub-object |
| `cert_rego_audit_eval_timing` | `false` | DEBUG: add `eval_us` per decision |
| `cert_rego_acl_include_payload` | `false` | Include publish payload in ACL input as `input.acl.payload_b64` (hot path) |
| `cert_rego_ocsp_timeout_ms` | `3000` | Per-request OCSP deadline when a policy calls `ocsp.check()` |
| `cert_rego_ocsp_min_refresh` | `86400` | Cache floor: don't re-query OCSP for the same cert more often than this |
| `cert_rego_ocsp_require_signing_eku` | `true` | Require `id-kp-OCSPSigning` on OCSP responders |
| `cert_rego_aia_fetch_enabled` | `false` | Download missing intermediates from AIA caIssuers URLs during chain verify |
| `cert_rego_aia_fetch_timeout_ms` | `3000` | Per-request HTTP deadline |
| `cert_rego_aia_fetch_max_depth` | `4` | Max intermediates to chase up the chain |
| `cert_rego_aia_fetch_max_size` | `65536` | Hard cap on response body bytes |
| `cert_rego_aia_fetch_cache_ttl` | `86400` | Seconds to keep a fetched CA cert in the URL cache |
| `cert_rego_crl_fetch_enabled` | `false` | Allow policies to call `crl.check()` which fetches CRLs from `crlDistributionPoints` URLs |
| `cert_rego_crl_fetch_timeout_ms` | `5000` | Per-request HTTP deadline |
| `cert_rego_crl_fetch_max_size` | `1048576` | Hard cap on response body bytes (1 MB) |
| `cert_rego_crl_fetch_cache_ttl` | `3600` | Seconds to keep a fetched CRL (clamped by its own `nextUpdate`) |

### Multiple trust roots

The plugin is designed for PKIs with more than one issuing authority — e.g. one CA for human operators and a separate CA for IoT devices. Point `cert_rego_ca_file` at a comma-separated list:

```
plugin_opt_cert_rego_ca_file /etc/mosquitto/ca/operator_bundle.pem,/etc/mosquitto/ca/device_bundle.pem
```

At connect time the plugin records which root the chain actually anchored to and exposes it under `input.cert.trust_anchor.fingerprint_sha256`. Policies typically compare that fingerprint against expected values (see [`examples/04_multi_root_ca.rego`](examples/04_multi_root_ca.rego)) to apply per-CA rules. The `client/gen_test_certs.sh` script has a `MULTI_ROOT=1` mode that produces a demo two-root PKI and prints the fingerprints for you.

## The Rego input document

### On CONNECT (`data.mqtt.connect`)

```jsonc
{
  "now_unix_ms": 1713456789012,
  "client": {
    "id": "client-abc",
    "address": "10.0.0.42",
    "protocol_version": 5
  },
  "cert": {
    "subject_dn": "CN=alice,O=Acme,C=US",
    "cn": "alice",
    "issuer_dn": "CN=Acme Intermediate,O=Acme,C=US",
    "serial": "1a2b3c...",
    "not_before_unix": 1700000000,
    "not_after_unix":  1800000000,
    "fingerprint_sha256": "hex...",
    "san": {
      "dns":   ["host.example.com"],
      "email": ["alice@example.com"],
      "uri":   []
    },
    "aia": {
      "ocsp_urls":       ["http://ocsp.example.com/"],
      "ca_issuers_urls": ["http://pki.example.com/intermediate.cer"]
    },
    "crl_urls": ["http://crl.example.com/intermediate.crl"],
    "custom_extensions": [
      {"oid": "1.3.6.1.4.1.99999.1", "critical": false,
       "value_type": "utf8string", "value": "fleet-a",
       "value_hex": "0c076669656c652d61"}
    ],
    "trust_anchor": {
      "subject_dn": "CN=Acme Operator Root,O=Acme,C=US",
      "fingerprint_sha256": "hex..."
    },
    "chain_ok": true,
    "chain_errors": [],
    "chain": [
      {"depth": 0, "subject_dn": "CN=alice,...",
       "issuer_dn": "CN=Acme Intermediate,...",
       "serial": "1a2b3c...", "fingerprint_sha256": "hex...",
       "not_before_unix": 1700000000, "not_after_unix": 1800000000,
       "verify_ok": true, "errors": []},
      {"depth": 1, "subject_dn": "CN=Acme Intermediate,...",
       "issuer_dn": "CN=Acme Operator Root,...",
       "serial": "01", "fingerprint_sha256": "hex...",
       "not_before_unix": 1600000000, "not_after_unix": 1900000000,
       "verify_ok": true, "errors": []},
      {"depth": 2, "subject_dn": "CN=Acme Operator Root,...",
       "issuer_dn": "CN=Acme Operator Root,...",
       "serial": "01", "fingerprint_sha256": "hex...",
       "not_before_unix": 1500000000, "not_after_unix": 2000000000,
       "verify_ok": true, "errors": []}
    ]
  },
  "connect": {
    "username": "alice"     // from CONNECT, may be "" or null
    // NOTE: no password field. This plugin is passwordless.
  }
}
```

`input.cert.trust_anchor` is the last certificate in the chain — **only populated when `chain_ok` is true**. On a broken chain it's `null` and the policy is expected to consult `input.cert.chain[last]` directly if it wants the structural anchor.

`input.cert.chain_ok` is the one-line baseline: `true` iff every cert in the chain verified cleanly. A policy that doesn't care about override semantics just gates on `input.cert.chain_ok`. A policy that wants to allow specific failure modes iterates `input.cert.chain[]` and inspects per-entry `verify_ok` + `errors[]`.

`input.cert.chain_errors[]` is a deduplicated convenience list of short failure codes seen across the whole chain. Codes are: `expired`, `not_yet_valid`, `issuer_unknown`, `bad_signature`, `self_signed`, `untrusted`, `crl_expired`, `revoked`, `invalid_ca`, `path_length_exceeded`, `invalid_purpose`, `chain_too_long`, `akid_mismatch`, `no_chain`, `other`. Each cert in `input.cert.chain[]` additionally carries its own `errors: [{code, message}]` array so policies can decide per-depth.

`input.cert.chain` is the full chain OpenSSL built (leaf to root), with `verify_ok` and `errors[]` per entry. Even on a totally broken chain, the leaf itself is always present at depth 0 so policies can reason about the cert they were presented.

`input.cert.aia` carries both Authority Information Access URL lists from the leaf's AIA extension: `ocsp_urls[]` and `ca_issuers_urls[]`. Policies can log them, match on them, or (if `cert_rego_aia_fetch_enabled` is on) rely on the plugin to auto-download missing intermediates from the caIssuers URLs during chain verify.

`input.cert.crl_urls` carries HTTP(S) URLs from the cert's `crlDistributionPoints` extension (note: this is a different extension from AIA — AIA holds OCSP and caIssuers URLs; CRL URLs live in their own extension, OID 2.5.29.31). The policy can log/match these, or call `crl.check()` and let the plugin fetch, verify, and cache the referenced CRLs.

`input.cert.custom_extensions` is an array of every X509 extension whose OID OpenSSL doesn't recognise — one object per extension with `oid` (dotted form), `critical` bool, `value_type` label (`utf8string`, `printablestring`, `ia5string`, `bmpstring`, `t61string`, `universalstring`, `visiblestring`, `octet_string`, `raw_ascii`, or `opaque`), `value` (decoded UTF-8 string, or `null`), and `value_hex` (raw DER of the extension content as a hex string). See [`examples/06_custom_oid.rego`](examples/06_custom_oid.rego) for the matching pattern.

### On ACL check (`data.mqtt.acl`)

Same `client` and `cert`, plus:

```jsonc
{
  "now_unix_ms": 1713456789012,
  "acl": {
    "action": "publish",          // "publish" | "subscribe" | "read" | "write"
    "topic":  "devices/alice/status",
    "qos":    1,
    "retain": false,
    "payload_b64": "..."          // only if cert_rego_acl_include_payload = true
  }
}
```

## External-service host functions

The plugin registers four host functions in [`rego_engine.cpp`](rego_engine.cpp) — three for LDAP, one for OCSP. Policies also have unrestricted access to rego-cpp's built-in `http.send` for OAuth2/OIDC introspection or any other HTTP-shaped lookup. Adding new native host functions (OS users, Kerberos, etc.) follows the same pattern: a small wrapper in a `*_query.c` + a few lines of registration in `rego_engine.cpp`.

```rego
# LDAP search. Returns a JSON string; policies call json.unmarshal to get
# an array of entry objects:
#   [{"dn": "...", "attrs": {"cn": ["alice"], "memberOf": ["..."]}}, ...]
# scope: "base" | "one" | "sub".  attrs: comma-separated, or "" for all.
# The bind credentials are the plugin's service account — never anything
# sent by the client.
ldap.search(url, bind_dn, bind_pw, base_dn, scope, filter, attrs)  ->  string

# Existence check — cheaper than a full search.
ldap.exists(url, bind_dn, bind_pw, base_dn, filter)  ->  bool

# Convenience: true iff `group_dn` has `member=user_dn`.
ldap.is_member(url, bind_dn, bind_pw, group_dn, user_dn)  ->  bool

# OCSP check over the current connection's verified chain. Returns a JSON
# string; json.unmarshal to get:
#   [{"depth":0, "subject_dn":"...", "status":"good"|"revoked"|"unknown"
#     |"error"|"skipped_root"|"no_issuer"|"no_aia",
#     "cached":bool, "error":string|null}, ...]
# The policy decides what statuses constitute "allow" — see example 05.
ocsp.check()  ->  string

# Attach a free-form note to the audit trail. Emitted as a `policy.note`
# event at DEBUG level, so it stays out of the way until the operator opts
# in. Always returns true so it composes inside rule bodies. Pass
# json.marshal(obj) for structured payloads.
audit.log(message)  ->  bool

# CRL check — same shape as ocsp.check() but against CRLs fetched from
# the cert's crlDistributionPoints extension. Every fetched CRL is
# cached by URL so repeated connects don't re-download; the cache is
# clamped by the CRL's nextUpdate. Policy decides strict/soft
# semantics — see example 07.
#   [{"depth":0, "subject_dn":"...", "status":"good"|"revoked"
#     |"expired_crl"|"unknown"|"error"|"skipped_root"|"no_dp"|"bad_sig",
#     "cached":bool, "error":string|null}, ...]
# Requires plugin_opt_cert_rego_crl_fetch_enabled=true; otherwise every
# entry is "error" with "crl_fetch_disabled".
crl.check()  ->  string
```

LDAP calls enforce the URL whitelist (`cert_rego_ldap_allowed_urls`). There is no `ldap.login` — the plugin is passwordless and no primitive takes a user-supplied password. There is no `ocsp_enabled` config — whether, how strictly, and for which certs to check is policy logic.

## Example policies

Five progressively-richer examples under [`examples/`](examples/):

1. [`01_minimal_allow_all.rego`](examples/01_minimal_allow_all.rego) — allow every cert-authenticated connection and any topic. Smoke-test baseline.
2. [`02_cn_topic_scope.rego`](examples/02_cn_topic_scope.rego) — CN-scoped topic namespace with a chain-validity-window check.
3. [`03_ldap_group_gate.rego`](examples/03_ldap_group_gate.rego) — connection gated on LDAP group membership plus structural chain-link integrity.
4. [`04_multi_root_ca.rego`](examples/04_multi_root_ca.rego) — trust-anchor dispatch plus per-anchor intermediate whitelist using `input.cert.chain[1]`.
5. [`05_ocsp_in_rego.rego`](examples/05_ocsp_in_rego.rego) — OCSP revocation check expressed entirely in Rego. Walks the per-depth `ocsp.check()` result.
6. [`06_custom_oid.rego`](examples/06_custom_oid.rego) — matching on custom certificate extensions, combined with chain-validity check.
7. [`07_crl_in_rego.rego`](examples/07_crl_in_rego.rego) — CRL revocation via `crl.check()`, including a combined OCSP + CRL belt-and-braces rule.
8. [`08_chain_traversal.rego`](examples/08_chain_traversal.rego) — how to **override** specific chain-verification failures. Shows the clean-baseline / selective-by-error-code / selective-by-cert-depth patterns.

## Reload behaviour

On SIGHUP the broker fires `MOSQ_EVT_RELOAD`. The plugin:

1. Parses the (possibly changed) options from the event.
2. Builds a fresh trust store from the new `ca_file`/`ca_path`.
3. Parses the (possibly changed) Rego policy into a fresh `Interpreter`.
4. Reopens the audit log.
5. Swaps all three pieces in atomically.

**If any step fails, the plugin keeps its previous state and logs a warning.** A broken policy file during reload will *not* leave the broker without auth.

## Rego compatibility notes

`rego-cpp` currently tracks upstream OPA's Rego v1.15.1. Most built-ins are present — including `json.*`, `time.*`, `http.*`, `net.*`, and `graphql.*`. The plugin still injects `input.now_unix_ms` at every eval so policies don't have to rely on `time.now_ns()` if they want a policy-agnostic "now".

Policies must use the **v0 Rego dialect** shown in the examples — no bare `if`/`contains` keywords. rego-cpp predates OPA's Rego v1 keyword tightening; the plugin enables `rego_v0` mode by default through rego-cpp's own defaults.

Policies may call `json.unmarshal(ldap.search(...))` to turn the string returned by `ldap.search` into a structured array of objects. We return the search result as a JSON string rather than as a pre-built Trieste Node tree so the C++ and C sides of the plugin can talk to each other without sharing any Rego AST types.

## Fail-closed semantics

**The only way to get a `MOSQ_ERR_SUCCESS` out of this plugin is by Rego explicitly evaluating a rule to `true`.** The default, in the absence of a Rego decision, is deny. The callback code enforces this as an invariant:

- `rc` starts at `MOSQ_ERR_AUTH` (basic auth) / `MOSQ_ERR_ACL_DENIED` (ACL).
- The only assignment to `MOSQ_ERR_SUCCESS` is reached after Rego returned `allow == true`.
- Every other exit path — missing Rego engine, OOM during chain build, JSON-input build failure, Rego eval error, Rego panic, undefined Rego result, explicit Rego deny — keeps the default-deny `rc`.

Specific situations:

- **No cert** → `MOSQ_ERR_PLUGIN_DEFER`. The plugin only speaks to TLS-with-client-cert traffic; cert-less connects fall through to other auth mechanisms the broker has configured. For strict cert-only auth on a listener, use mosquitto's own `require_certificate true` — that rejects the TLS handshake before the plugin is even consulted.
- **No policy file configured** → plugin hard-fails at init (startup). Broker refuses to load the plugin. This is deliberate: a silent deny-all fallback would hide operator misconfiguration.
- **Policy file unparseable** → plugin hard-fails at init. Same reasoning.
- **Policy file reloadable but broken reload** → plugin keeps the previous working policy and logs a warning; broker stays up with the old rules. (Not the same as init.)
- **No Rego engine at runtime** (defence in depth; should be unreachable) → deny + audit event with `stage:"no_rego_engine"`.
- **Chain verify fails** → **does not auto-deny**. The plugin runs the verification callback in collecting mode, gathers every per-cert error, and passes the full picture to Rego. The policy decides whether to accept (e.g. override an expired intermediate) or deny. Policies that want the baseline auto-deny behaviour gate on `input.cert.chain_ok`.
- **Rego eval error** (parse, panic, timeout, missing entrypoint) → deny.
- **Rego returns undefined** → deny. (rego-cpp maps undefined results to falsy for our boolean entrypoints.)
- **LDAP host function error inside policy** → the call returns undefined in Rego, which under a fail-closed policy means deny.
- **OCSP / CRL responder unreachable from inside a host function** → `ocsp.check()` / `crl.check()` surface the failure as `status:"error"` in their per-cert arrays; the policy decides whether that's tolerable or not.
- **Audit log open fails** → plugin still runs, audit logs silently drop (never blocks auth).

## Logging

Two channels:

1. **Broker log** via `mosquitto_log_printf` — operational events at `NOTICE`/`INFO`/`DEBUG`, never credentials.
2. **Audit log** — structured JSON, one event per line. Two sinks (file and syslog) speak the same line format; either or both can be enabled. A single level filter applies to both, so file and syslog stay in sync.

Each line carries `ts`, `level`, `event`, optional `result`, plus event-specific extras. Example INFO-level allow line under a relaxed policy:

```json
{"ts":"2026-04-15T07:30:01.123Z","level":"info","event":"connect","result":"allow",
 "client_id":"sensor-12","remote_addr":"10.0.0.42","decision_id":4711,
 "cn":"sensor-12","subject_dn":"CN=sensor-12,O=acme,C=US",
 "issuer_dn":"CN=Acme Device Intermediate,O=acme,C=US",
 "serial":"1a2b3c","fingerprint_sha256":"abc...",
 "trust_anchor_fp":"def...","chain_ok":true,"chain_errors":[]}
```

### Levels

| Level | What's emitted |
|---|---|
| `error` | internal plugin failures (no rego engine, JSON build OOM) |
| `warn` | + chain build / verify_error denies, sink-write failures |
| `notice` | + plugin lifecycle (`plugin.init/reload/shutdown`) and **deny decisions** (production deny-only sink) |
| `info` (default) | + **allow decisions** with full cert metadata. Visible-by-default for relaxed policies. |
| `debug` | + per-cert chain dump (truncated), SAN, custom OIDs, `eval_us` per decision, `policy.note` events injected by Rego's `audit.log()` |

### Truncation

Every line is bounded by `cert_rego_audit_line_cap` (default 4096 bytes; 1024..16384). DNs in the chain dump are individually truncated to 256 chars (UTF-8 ellipsis `\u2026` appended). The chain dump itself is capped at `cert_rego_audit_chain_max_depth` entries (default 8); deeper chains get a `"chain_truncated":true` marker. If the assembled line still exceeds the cap, the extras are dropped and the line is reissued as the minimal `{"ts":...,"level":...,"event":...,"result":...,"truncated":true}` form.

### Syslog

When `cert_rego_audit_syslog_enabled true` the same JSON line is forwarded via `syslog(3)` at the corresponding priority (`error`→`LOG_ERR`, `warn`→`LOG_WARNING`, `notice`→`LOG_NOTICE`, `info`→`LOG_INFO`, `debug`→`LOG_DEBUG`). Default ident is `mosquitto-cert-rego`, default facility is `authpriv` — picked up by rsyslog/journald and parseable as JSON by every modern SIEM.

### Policy-side audit

A Rego policy can attach a free-form note to the audit trail with the `audit.log(message)` host function:

```rego
allow {
    input.cert.cn != ""
    chain_ok_or_tolerable_expiry
    audit.log(sprintf("override:expired_intermediate cn=%s", [input.cert.cn]))
}
```

The note is emitted as a `policy.note` event at DEBUG level — invisible at the default INFO threshold but available when chasing why a particular decision went the way it did. `audit.log` always returns `true` so it composes inside rule bodies; passing `json.marshal(obj)` lets policies attach structured payloads.

The file sink is append-only; use `logrotate` with `copytruncate` for rotation.

## Limitations

- Single plugin instance per broker process. The rego-cpp callback API takes plain function pointers with no user_data slot, so the plugin-wide pointer lives in a file-scope static inside `rego_engine.cpp`.
- LDAP simple bind only (for the service-account bind used by `ldap.search` / `ldap.exists` / `ldap.is_member`). No SASL, no GSSAPI, no mTLS-to-LDAP.
- No persistent cache. Restart clears the OCSP and LDAP search caches.
- rego-cpp's dialect is mandatory — v1-flavoured Rego with bare `if`/`contains` keywords won't parse.

## License

EPL-2.0 OR BSD-3-Clause, matching upstream mosquitto's first-class plugins.
