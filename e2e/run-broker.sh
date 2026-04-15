#!/usr/bin/env bash
# Bring up the e2e mosquitto broker with the cert-rego plugin loaded.
#
# Usage: ./e2e/run-broker.sh [--foreground|-f]
#   default: backgrounded; PID written to e2e/run/broker.pid
#   -f:      runs in foreground (Ctrl-C to stop)

set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "${E2E_DIR}")"
PLUGIN_SO="${PLUGIN_SO:-/tmp/cert-rego-build/mosquitto_cert_rego.so}"
MOSQUITTO_BIN="${MOSQUITTO_BIN:-/home/hs/mosquitto/build/src/mosquitto}"

if [ ! -f "${PLUGIN_SO}" ]; then
    echo "plugin .so not found at ${PLUGIN_SO}" >&2
    echo "build it first:  cmake --build /tmp/cert-rego-build" >&2
    exit 1
fi
if [ ! -f "${E2E_DIR}/pki/bundle_all.pem" ]; then
    echo "PKI not generated. Run:" >&2
    echo "  cd ${REPO_DIR} && MULTI_ROOT=1 ./client/gen_test_certs.sh e2e/pki" >&2
    exit 1
fi

mkdir -p "${E2E_DIR}/run"

# Compute the trust-anchor fingerprints fresh from the on-disk certs and
# stamp them into the policy. The policy file lives in source; we render
# the runtime copy under run/.
fp_a=$(openssl x509 -in "${E2E_DIR}/pki/root_a.crt" -noout -fingerprint -sha256 \
    | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')
fp_b=$(openssl x509 -in "${E2E_DIR}/pki/root_b.crt" -noout -fingerprint -sha256 \
    | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')

sed \
    -e "s|__ROOT_A_FP__|${fp_a}|g" \
    -e "s|__ROOT_B_FP__|${fp_b}|g" \
    "${E2E_DIR}/policy.rego" > "${E2E_DIR}/run/policy.rego"

sed \
    -e "s|__E2E_DIR__|${E2E_DIR}|g" \
    -e "s|__PLUGIN_SO__|${PLUGIN_SO}|g" \
    "${E2E_DIR}/mosquitto.conf" > "${E2E_DIR}/run/mosquitto.conf"

# The runtime conf points policy_file at run/policy.rego (the stamped copy),
# not the un-substituted source. The first sed above already replaced
# __E2E_DIR__; this replaces the resulting absolute path pointing at the
# template with the absolute path of the stamped copy.
sed -i "s|${E2E_DIR}/policy.rego|${E2E_DIR}/run/policy.rego|g" \
    "${E2E_DIR}/run/mosquitto.conf"

CONF="${E2E_DIR}/run/mosquitto.conf"
PIDFILE="${E2E_DIR}/run/broker.pid"

if [ "${1:-}" = "-f" ] || [ "${1:-}" = "--foreground" ]; then
    exec "${MOSQUITTO_BIN}" -c "${CONF}" -v
fi

if [ -f "${PIDFILE}" ] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null; then
    echo "broker already running, pid $(cat "${PIDFILE}")"
    exit 0
fi

# Truncate audit log between runs so test assertions are fresh.
: > "${E2E_DIR}/run/audit.jsonl"
: > "${E2E_DIR}/run/broker.log"

"${MOSQUITTO_BIN}" -c "${CONF}" -v >"${E2E_DIR}/run/broker.stdout" 2>&1 &
echo $! > "${PIDFILE}"

# Wait for the listener to actually accept connections.
for i in $(seq 1 50); do
    if ss -ltn 2>/dev/null | grep -q ':18883 '; then
        echo "broker up (pid $(cat "${PIDFILE}"), port 18883)"
        exit 0
    fi
    sleep 0.1
done

echo "broker failed to come up — see ${E2E_DIR}/run/broker.stdout" >&2
cat "${E2E_DIR}/run/broker.stdout" >&2
exit 1
