# e2e test policy for cert-rego.
#
# Multi-root dispatch:
#   - root_a (operator CA) clients can publish/subscribe under "devices/+/..."
#     and subscribe to "$SYS/#"
#   - root_b (device CA)   clients only see their own subtree
#                          "devices/<cn>/..." for read+write+subscribe
#
# Both roots require a clean chain (chain_ok). audit.log() notes the role
# at decision time so DEBUG logging carries the dispatch reason.
#
# Fingerprints are filled in by run-broker.sh from the generated PKI.

package mqtt

root_a_fp := "__ROOT_A_FP__"  # operator CA
root_b_fp := "__ROOT_B_FP__"  # device CA

anchor_fp := input.cert.trust_anchor.fingerprint_sha256

is_operator { anchor_fp == root_a_fp }
is_device   { anchor_fp == root_b_fp }

default connect := false
default acl := false

connect {
    input.cert.chain_ok
    input.cert.cn != ""
    is_operator
    audit.log(sprintf("role=operator cn=%s", [input.cert.cn]))
}

connect {
    input.cert.chain_ok
    input.cert.cn != ""
    is_device
    audit.log(sprintf("role=device cn=%s", [input.cert.cn]))
}

# Operators: full devices/* + $SYS/# subscribe.
acl {
    is_operator
    startswith(input.acl.topic, "devices/")
}

acl {
    is_operator
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "$SYS/")
}

# Devices: own subtree only. Includes write, read, and subscribe.
acl {
    is_device
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}
