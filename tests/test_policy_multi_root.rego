# Test policy for the multi-root test cases in test_rego.cpp.
#
# The fingerprints below are fake — the test synthesises input documents
# with whichever trust_anchor fingerprint it wants and asserts the
# policy dispatches correctly. No real PKI involved.

package mqtt

operator_fp := "aaaa000000000000000000000000000000000000000000000000000000000000"
device_fp   := "bbbb000000000000000000000000000000000000000000000000000000000000"

is_operator { input.cert.trust_anchor.fingerprint_sha256 == operator_fp }
is_device   { input.cert.trust_anchor.fingerprint_sha256 == device_fp }

default connect := false
default acl := false

connect { is_operator; input.cert.cn != "" }
connect { is_device;   input.cert.cn != "" }

# Operators: full access under devices/.
acl {
    is_operator
    startswith(input.acl.topic, "devices/")
}

# Devices: own subtree only.
acl {
    is_device
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}
