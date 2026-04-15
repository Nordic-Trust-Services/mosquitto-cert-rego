#!/usr/bin/env bash
# Run the cybersec suite against a sanitizer-instrumented broker.
#
# Builds the plugin with -fsanitize=address,undefined into a separate
# build dir, restarts the broker with LD_PRELOAD=libasan.so + the
# sanitizer-built plugin, and runs cybersec.py end-to-end.
#
# ASan/UBSan reports go to e2e/run/asan.log. Any *.SUMMARY: line in
# that log fails the run.

set -euo pipefail
E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
SAN_BUILD_DIR="${PLUGIN_BUILD_DIR:-/tmp/cert-rego-build-asan}"
SAN_PLUGIN="${SAN_BUILD_DIR}/mosquitto_cert_rego.so"
LIBASAN="$(gcc -print-file-name=libasan.so)"
ASAN_LOG="${E2E_DIR}/run/asan.log"

if [ ! -f "${SAN_PLUGIN}" ]; then
    echo "==> sanitizer plugin not found, building"
    "${E2E_DIR}/build-asan.sh" >/dev/null
fi

# Stop any running broker, drop a marker, restart with sanitizer env.
"${E2E_DIR}/stop-broker.sh" >/dev/null || true
mkdir -p "${E2E_DIR}/run"
: > "${ASAN_LOG}"

# detect_leaks=0 — mosquitto on shutdown leaves intentional one-time
# allocations that aren't true leaks; turning it on would fail every run.
# halt_on_error=0 keeps the broker alive across reports so we can collect
# multiple in one run; we still grep for SUMMARY at the end.
export ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:detect_leaks=0:log_path=${ASAN_LOG}:print_summary=1:strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1"
export UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1:log_path=${ASAN_LOG}"
export LD_PRELOAD="${LIBASAN}"
export PLUGIN_SO="${SAN_PLUGIN}"

echo "==> starting broker (sanitizer-instrumented)"
"${E2E_DIR}/run-broker.sh"

cleanup() { "${E2E_DIR}/stop-broker.sh" >/dev/null || true; }
trap cleanup EXIT

echo
echo "==> cybersec under sanitizers"
"${E2E_DIR}/cybersec.py" "$@" || cybersec_rc=$?
cybersec_rc=${cybersec_rc:-0}

# Flush the broker so any pending sanitizer reports land.
"${E2E_DIR}/stop-broker.sh" >/dev/null
sleep 0.3

echo
# log_path causes ASan to write to ${ASAN_LOG}.<pid> instead of the literal
# path. Aggregate all of them.
shopt -s nullglob
report_files=("${ASAN_LOG}"*)
if [ ${#report_files[@]} -eq 0 ]; then
    echo "==> no ASan/UBSan reports written"
else
    echo "==> ASan/UBSan output:"
    cat "${report_files[@]}" | tee "${ASAN_LOG}.combined" | head -200
    if grep -q 'SUMMARY:' "${ASAN_LOG}.combined"; then
        echo
        echo "FAIL: sanitizer reported one or more issues"
        exit 1
    fi
    if grep -qE 'runtime error|stack-buffer-overflow|heap-buffer-overflow|use-after-free' "${ASAN_LOG}.combined"; then
        echo
        echo "FAIL: sanitizer reported a runtime error"
        exit 1
    fi
fi

if [ "${cybersec_rc}" -ne 0 ]; then
    echo "FAIL: cybersec suite returned ${cybersec_rc}"
    exit "${cybersec_rc}"
fi

echo
echo "asan suite OK"
