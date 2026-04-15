# Contributing

Thanks for looking. This file covers the build, the layout, and the things worth knowing before sending a patch.

## Building from a fresh clone

The plugin depends on [rego-cpp](https://github.com/microsoft/rego-cpp), which is not packaged in most distros. You build it from source once, install it to a local prefix, and point the plugin build at that prefix.

```bash
# 1. rego-cpp
git clone https://github.com/microsoft/rego-cpp.git /tmp/rego-cpp
cmake -B /tmp/rego-cpp/build -S /tmp/rego-cpp \
    -DCMAKE_INSTALL_PREFIX=/opt/regocpp \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DREGOCPP_BUILD_TESTS=OFF \
    -DREGOCPP_BUILD_TOOLS=OFF
cmake --build /tmp/rego-cpp/build -j
sudo cmake --install /tmp/rego-cpp/build

# The rego-cpp install currently misses the transitive trieste/snmalloc
# headers. Until upstream fixes that, copy them across:
sudo cp -r /tmp/rego-cpp/build/_deps/trieste-src/include/*      /opt/regocpp/include/
sudo cp -r /tmp/rego-cpp/build/_deps/trieste-build/include/*    /opt/regocpp/include/
sudo cp -r /tmp/rego-cpp/build/_deps/snmalloc-src/src/snmalloc  /opt/regocpp/include/

# 2. system deps
sudo apt install libssl-dev libcjson-dev libldap2-dev libmosquitto-dev

# 3. plugin
cmake -B build -S . -DREGOCPP_ROOT=/opt/regocpp
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The [`.github/workflows/build.yml`](.github/workflows/build.yml) CI workflow does the same thing in Docker and is the canonical reference if the manual steps above drift.

## Layout

| Path | What it is |
|---|---|
| `plugin.c` | Mosquitto plugin entry points + callbacks (BASIC_AUTH, ACL_CHECK, RELOAD) |
| `cert_parse.c` | X509 field extraction → Rego input JSON builder |
| `ocsp_check.c` | `ca_verify_chain` (collecting-mode) + OCSP walker |
| `crl_check.c` | CRL inspection driver (called from `crl.check()` host function) |
| `aia_fetch.c`, `crl_fetch.c` | HTTP-based cert/CRL fetchers with URL-keyed caches |
| `http_fetch.c` | Shared HTTP/HTTPS GET primitive |
| `ldap_query.c` | libldap wrapper for the LDAP host functions |
| `cache.c` | In-memory OCSP + LDAP-search blob cache |
| `audit_log.c` | JSON-lines audit log sink |
| `rego_engine.cpp` | **Only C++ TU.** Wraps rego-cpp's `Interpreter`, registers the `ldap.*` / `ocsp.check` / `crl.check` host functions |
| `cert_auth.h` | Shared header (internal name; the project was renamed from cert-auth to cert-rego but the header kept its legacy filename to minimise churn) |
| `examples/` | Example Rego policies, 01 → 08 progressively richer |
| `client/` | Reference Python MQTT client + test PKI generator |
| `tests/` | ctest harness: `test_rego_engine` runs the rego-cpp integration against two test policies |

## Design invariants

Don't break these without discussing first:

1. **Rego is authoritative.** The only way to return `MOSQ_ERR_SUCCESS` from a callback is after Rego evaluates the policy to `allow == true`. Every other path is deny.
2. **Chain verification is collecting, not aborting.** Rego sees every per-cert error; the policy may choose to override specific failure modes.
3. **Passwordless.** No MQTT CONNECT password reaches Rego or any LDAP call. All LDAP binds use the plugin's service-account credentials from config.
4. **External services are Rego host functions.** The client never sees LDAP / OCSP / CRL / HTTP calls; the broker's audit log does.
5. **All network lookups are cached.** OCSP, CRL, LDAP search, fetched CA certs — all have in-memory caches with TTLs clamped by the upstream response where applicable.

## Code style

- C11 for the .c files, C++20 for `rego_engine.cpp` (required by rego-cpp's public headers).
- Warnings: `-Wall -Wextra -Wconversion -Wshadow` on C; `-Wall -Wextra` on C++ (-Wshadow disabled for C++ because mosquitto's own `broker.h` isn't clean under it).
- Tabs for indentation in C files (matches upstream mosquitto); 4 spaces in `.rego` files (matches OPA convention).
- Every allocation uses `mosquitto_malloc` / `mosquitto_strdup` etc. so the broker's memory tracking sees it.
- No heap allocations in fast paths beyond what the input-doc build already requires; audit the hot path (basic_auth + acl_check + ocsp.check + crl.check).

## Commit messages

Conventional and terse. The SPDX headers (`SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause`) must stay on every source file.

## Reporting a vulnerability

Do not open a public issue. Email the maintainers directly at the address on the repository's main README.
