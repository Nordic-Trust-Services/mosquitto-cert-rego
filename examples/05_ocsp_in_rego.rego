# 05_ocsp_in_rego.rego
#
# OCSP as a policy decision. ocsp.check() returns a JSON string;
# json.unmarshal it to get an array of per-cert status objects:
#
#   [{"depth":0, "subject_dn":"...", "status":"good", "cached":true, "error":null},
#    {"depth":1, "subject_dn":"...", "status":"good", "cached":false, "error":null},
#    {"depth":2, "subject_dn":"...", "status":"skipped_root", ...}]
#
# status: good / revoked / unknown / error / skipped_root / no_issuer / no_aia

package mqtt

ocsp_statuses := json.unmarshal(ocsp.check())

# Strict: all non-root certs must be "good". No errors tolerated.
ocsp_strict_ok {
    not ocsp_bad_exists
}

ocsp_bad_exists {
    some i
    not is_ok_status(ocsp_statuses[i].status)
}

is_ok_status(s) { s == "good" }
is_ok_status(s) { s == "skipped_root" }

# Soft: only an explicit "revoked" kills. Errors / unknowns tolerated.
ocsp_soft_ok { not ocsp_any_revoked }

ocsp_any_revoked {
    some i
    ocsp_statuses[i].status == "revoked"
}

# Leaf-only: only the leaf must be good.
ocsp_leaf_only_ok {
    ocsp_statuses[0].status == "good"
}

default connect := false
default acl := false

# Default example: require a CN and strict-OCSP the whole chain.
connect {
    input.cert.chain_ok
    input.cert.cn != ""
    ocsp_strict_ok
}

# ACL: OCSP typically runs at connect time — ACL checks trust the
# connection for its lifetime to avoid per-publish fetch storms.
acl {
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}
