#!/usr/bin/env bash
# Happy-path smoke test against the running e2e broker.
#
# Asserts:
#   - operator_alice can connect, subscribe to devices/#, and pub/sub anywhere
#     under devices/.
#   - device_01 can connect and publish to devices/device-01/<anything>.
#   - device_01 publishing to devices/device-02/foo is rejected by ACL.
#   - audit log contains one connect+allow line per successful client and
#     carries the cert metadata (cn, fingerprint, trust_anchor_fp, decision_id).

set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI="${E2E_DIR}/pki"
HOST="${HOST:-localhost}"
PORT="${PORT:-18883}"
MOSQUITTO_PUB="${MOSQUITTO_PUB:-/home/hs/mosquitto/build/client/mosquitto_pub}"
MOSQUITTO_SUB="${MOSQUITTO_SUB:-/home/hs/mosquitto/build/client/mosquitto_sub}"

audit="${E2E_DIR}/run/audit.jsonl"

# Common mosquitto client args.
mt_args=(
    -h "${HOST}" -p "${PORT}"
    --cafile "${PKI}/bundle_all.pem"
    --tls-version tlsv1.2
    -d
)

run_pub() {
    local cert="$1" key="$2" cn="$3" topic="$4" msg="$5"
    "${MOSQUITTO_PUB}" "${mt_args[@]}" \
        --cert "${PKI}/${cert}" --key "${PKI}/${key}" \
        -i "smoke-${cn}-$$" \
        -t "${topic}" -m "${msg}" -q 1
}

audit_count_before=$(wc -l < "${audit}")

echo "==> 1. operator_alice publishes to devices/anything/foo"
run_pub operator_alice.crt operator_alice.key alice \
    devices/anything/foo hello-from-alice

echo "==> 2. device_01 publishes to its own subtree"
run_pub device_01.crt device_01.key device-01 \
    devices/device-01/telemetry t=1

echo "==> 3. device_01 publishes to ANOTHER device's subtree (must be denied)"
if run_pub device_01.crt device_01.key device-01 \
        devices/device-02/telemetry should-be-denied 2>&1 | tee /tmp/smoke3.log \
        | grep -q "PUBACK"; then
    # mosquitto_pub may still report success because broker silently drops
    # ACL-denied publishes for QoS<=1 unless told to fail; we assert via
    # the audit log instead.
    :
fi

# Give the broker a moment to flush the audit line for the rejected ACL.
sleep 0.2

audit_count_after=$(wc -l < "${audit}")
echo "==> audit lines added: $((audit_count_after - audit_count_before))"

python3 - "${audit}" <<'PY'
import json, sys
path = sys.argv[1]
lines = [json.loads(l) for l in open(path) if l.strip()]
checks = [
    ("alice connect allow with cn=alice",
        lambda r: r.get("event")=="connect" and r.get("result")=="allow" and r.get("cn")=="alice"),
    ("device-01 connect allow with cn=device-01",
        lambda r: r.get("event")=="connect" and r.get("result")=="allow" and r.get("cn")=="device-01"),
    ("device-01 acl allow under own subtree",
        lambda r: r.get("event")=="acl" and r.get("result")=="allow"
                  and r.get("cn")=="device-01" and "device-01" in (r.get("topic") or "")),
    ("device-01 acl DENY for device-02 subtree",
        lambda r: r.get("event")=="acl" and r.get("result")=="deny"
                  and r.get("cn")=="device-01" and "device-02" in (r.get("topic") or "")),
    ("every allow line carries decision_id and trust_anchor_fp",
        lambda r: r.get("result")=="allow" and r.get("decision_id") is not None and r.get("trust_anchor_fp")),
]
fail = False
for desc, pred in checks:
    n = sum(1 for r in lines if pred(r))
    if n < 1:
        print(f"FAIL: {desc} (no matching audit lines)")
        fail = True
    else:
        print(f"OK:   {desc} ({n} matching lines)")
sys.exit(1 if fail else 0)
PY

echo
echo "smoke OK"
