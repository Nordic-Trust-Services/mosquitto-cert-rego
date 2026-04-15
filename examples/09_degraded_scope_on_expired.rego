# 09_degraded_scope_on_expired.rego
#
# Graceful degradation on an expired chain.
#
#   * A fully-verified chain  → full access under "devices/<cn>/...".
#   * A chain whose ONLY fault is expiry (leaf or intermediate) → a
#     reduced subset: the device may still publish heartbeat/status and
#     subscribe to a rotation advisory topic, so operators can tell a
#     neglected device to refresh its cert without locking it out
#     entirely. Writes to data/config topics are denied.
#   * Any other chain error (bad signature, unknown issuer, revoked,
#     not_yet_valid, etc.) → deny connect outright.
#
# Rationale: a field device with an expired cert is a known, benign
# failure mode — it just missed its renewal window. We want to keep a
# control channel open long enough to rotate it, not brick it. Harder
# failures (issuer_unknown, bad_signature, revoked) do not get this
# courtesy.

package mqtt

# ---- posture detection ------------------------------------------------

chain_clean { input.cert.chain_ok }

# True iff every chain error present is "expired". One or more expiries
# anywhere in the chain is tolerated; anything else disqualifies.
chain_expired_only {
    count(input.cert.chain_errors) > 0
    unexpected := {c |
        some i
        c := input.cert.chain_errors[i]
        c != "expired"
    }
    count(unexpected) == 0
}

# ---- connect ----------------------------------------------------------

default connect := false

connect {
    input.cert.cn != ""
    chain_clean
}

connect {
    input.cert.cn != ""
    chain_expired_only
}

# ---- acl --------------------------------------------------------------

default acl := false

# Full access: clean chain, device's own namespace, any action.
acl {
    chain_clean
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}

# Degraded: publish heartbeat/status under the device's own namespace.
acl {
    chain_expired_only
    input.acl.action == "write"
    allowed_degraded_publish_topics[_] == degraded_suffix
}

degraded_suffix := suffix {
    prefix := sprintf("devices/%s/", [input.cert.cn])
    startswith(input.acl.topic, prefix)
    suffix := substring(input.acl.topic, count(prefix), -1)
}

allowed_degraded_publish_topics := {"status", "heartbeat"}

# Degraded: subscribe to the cert-rotation advisory topic so the
# operator / fleet manager can tell this specific device to renew.
acl {
    chain_expired_only
    input.acl.action == "subscribe"
    input.acl.topic == sprintf("devices/%s/cert/rotate", [input.cert.cn])
}
