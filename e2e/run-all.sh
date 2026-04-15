#!/usr/bin/env bash
# Orchestrator: generate PKI (if missing), start broker, run smoke + cybersec
# suites, stop broker. Exit non-zero on any failure.

set -euo pipefail
E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "${E2E_DIR}")"

cleanup() { "${E2E_DIR}/stop-broker.sh" >/dev/null || true; }
trap cleanup EXIT

if [ ! -f "${E2E_DIR}/pki/bundle_all.pem" ]; then
    echo "==> generating multi-root PKI"
    ( cd "${REPO_DIR}" && MULTI_ROOT=1 ./client/gen_test_certs.sh e2e/pki )
fi
if [ ! -f "${E2E_DIR}/pki/expired_alice.crt" ]; then
    echo "==> generating negative-case certs"
    "${E2E_DIR}/gen-negative-certs.sh"
fi
if [ ! -f "${E2E_DIR}/pki/ocsp_signer.crt" ]; then
    echo "==> generating OCSP fixtures"
    "${E2E_DIR}/_gen_ocsp_fixtures.py" "${E2E_DIR}/pki"
fi

"${E2E_DIR}/stop-broker.sh" >/dev/null || true
"${E2E_DIR}/run-broker.sh"

echo
echo "==> smoke"
"${E2E_DIR}/smoke.sh"

echo
echo "==> cybersec"
"${E2E_DIR}/cybersec.py"
