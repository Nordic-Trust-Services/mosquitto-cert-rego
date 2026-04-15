# 02_cn_topic_scope.rego
#
# Topic scoping by certificate CN, with a chain validity-window check.
#
#   * A client connects iff its cert has a CN AND every cert in its
#     verified chain is currently within its validity window.
#   * That client may publish, subscribe, read, and write only under
#     "devices/<cn>/". Everything else is denied.

package mqtt

now_sec := input.now_unix_ms / 1000

# Every cert in the verified chain is still valid at input.now_unix_ms.
# The plugin has already checked signatures; this is the policy-level
# time-of-use check that keeps a recently-expired cert out even if the
# trust-anchor build predated expiry.
chain_currently_valid { not chain_validity_breach_exists }
chain_validity_breach_exists {
    some i
    input.cert.chain[i].not_before_unix > now_sec
}
chain_validity_breach_exists {
    some i
    input.cert.chain[i].not_after_unix <= now_sec
}

default connect := false
default acl := false

connect {
    input.cert.chain_ok
    input.cert.cn != ""
    chain_currently_valid
}

acl {
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}
