#!/usr/bin/env bash
# Build the cert-rego plugin with AddressSanitizer + UndefinedBehaviorSanitizer
# instrumentation into /tmp/cert-rego-build-asan/.
#
# Usage:
#   ./e2e/build-asan.sh              # configure + build
#   PLUGIN_BUILD_DIR=/path ./e2e/build-asan.sh   # custom output dir
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PLUGIN_BUILD_DIR:-/tmp/cert-rego-build-asan}"

# rego-cpp is built without sanitizers (system install). Mixing sanitized and
# non-sanitized objects works as long as the sanitizer runtime is preloaded
# at runtime (libasan/libubsan must come first in the link order). For our
# plugin .so we just compile + link with -fsanitize=...; the broker LD_PRELOADs
# libasan.so so allocator interception is global.
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake -S "${REPO_DIR}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="${SAN} -g -O1" \
    -DCMAKE_CXX_FLAGS="${SAN} -g -O1" \
    -DCMAKE_MODULE_LINKER_FLAGS="${SAN}" \
    -DCMAKE_EXE_LINKER_FLAGS="${SAN}" \
    -DCMAKE_SHARED_LINKER_FLAGS="${SAN}" \
    -DLDAP_INCLUDE_DIR=/tmp/ldap_stub \
    -DLDAP_LIBRARIES=/lib/x86_64-linux-gnu/libldap-2.5.so.0 \
    -DLBER_LIBRARIES=/lib/x86_64-linux-gnu/liblber-2.5.so.0 \
    -DREGOCPP_ROOT=/tmp/rego-cpp-install \
    -DMOSQUITTO_INCLUDE_DIR=/home/hs/mosquitto/include 1>&2

cmake --build . -j"$(nproc)" 1>&2

echo "${BUILD_DIR}/mosquitto_cert_rego.so"
