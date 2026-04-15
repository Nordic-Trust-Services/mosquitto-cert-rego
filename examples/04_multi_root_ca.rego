# 04_multi_root_ca.rego
#
# Multi-root dispatch + per-anchor intermediate whitelist.
#
# The broker trusts two roots:
#   root_a  — operator CA (humans)
#   root_b  — device CA   (IoT fleet)
#
# Plain "chain up to root_a/root_b" isn't always enough — in real PKIs
# the root delegates to several sub-CAs and only a subset should issue
# MQTT client certs. The pattern below:
#
#   1. identify the trust anchor by SHA-256 fingerprint
#   2. pull the intermediate that signed the leaf from input.cert.chain
#   3. require that intermediate's fingerprint to be on an anchor-
#      specific allow list
#
# This lets you accept operators from root_a but reject operators from
# root_a's DR sub-CA if you haven't enrolled that sub-CA for MQTT yet,
# all without changing the trust store.

package mqtt

# Fingerprints from gen_test_certs.sh --multi-root. Replace with yours.
root_a_fp := "REPLACE_WITH_ROOT_A_SHA256_FINGERPRINT"
root_b_fp := "REPLACE_WITH_ROOT_B_SHA256_FINGERPRINT"

# Per-anchor intermediate allow-lists. Chain[1] — the cert that signed
# the leaf — must match one of these. Populate with the SHA-256 of each
# issuing intermediate under the respective root.
approved_operator_intermediates := {
    "REPLACE_WITH_OPERATOR_INT_A_FP",
    "REPLACE_WITH_OPERATOR_INT_B_FP",
}
approved_device_intermediates := {
    "REPLACE_WITH_DEVICE_INT_A_FP",
}

anchor_fp := input.cert.trust_anchor.fingerprint_sha256

is_operator { anchor_fp == root_a_fp }
is_device   { anchor_fp == root_b_fp }

# The intermediate directly above the leaf.
leaf_issuer := input.cert.chain[1]

issuing_intermediate_approved_for_operator {
    is_operator
    approved_operator_intermediates[leaf_issuer.fingerprint_sha256]
}

issuing_intermediate_approved_for_device {
    is_device
    approved_device_intermediates[leaf_issuer.fingerprint_sha256]
}

default connect := false
default acl := false

connect {
    input.cert.chain_ok
    is_operator
    input.cert.cn != ""
    issuing_intermediate_approved_for_operator
}

connect {
    input.cert.chain_ok
    is_device
    input.cert.cn != ""
    issuing_intermediate_approved_for_device
}

# Operators: full access to devices/*, subscribe-only on $SYS/#.
acl {
    is_operator
    startswith(input.acl.topic, "devices/")
}

acl {
    is_operator
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "$SYS/")
}

# Devices: own subtree only (write + subscribe).
acl {
    is_device
    input.acl.action == "write"
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}

acl {
    is_device
    input.acl.action == "subscribe"
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}
