# 10_san_uri_roles.rego
#
# Role-based access driven by URN-shaped URIs in the cert's SAN extension.
#
# A common PKI pattern: the cert's Subject Alternative Name extension
# carries one or more URI entries that encode the client's role(s), e.g.
#
#     X509v3 Subject Alternative Name:
#         URI: urn:iotwidgits:role:admin
#         URI: urn:iotwidgits:fleet:north
#
# These flow into the Rego input doc as `input.cert.san.uri` (an array of
# strings). Policies match on membership to grant topic scope — no LDAP
# or external lookup needed for the hot path, because the issuer already
# vouched for the role when signing the cert.
#
# Advantages over CN-based role checks:
#   * CN is a single string; SAN URIs are a set — a cert can carry
#     multiple roles without smuggling them into a CN via delimiters.
#   * SAN URIs survive rename: you don't pivot authz when a device's
#     operator changes its display name.
#   * The OID scheme (`urn:<vendor>:role:<name>`) is explicit and hard
#     to collide with arbitrary CNs.
#
# Policy outline:
#   * admin role  → full read/write on "ops/#"
#   * fleet role (with a fleet name)  → read/write on "fleet/<name>/#"
#   * reader role → subscribe-only on "ops/# + fleet/#"
#   * a cert with no recognised role → deny

package mqtt

# ---- role extraction ---------------------------------------------------

# Every URI that looks like a urn:iotwidgits:role:<name>
roles[r] {
    some i
    uri := input.cert.san.uri[i]
    startswith(uri, "urn:iotwidgits:role:")
    r := substring(uri, count("urn:iotwidgits:role:"), -1)
}

# Every fleet the cert is a member of, e.g. urn:iotwidgits:fleet:north -> "north"
fleets[f] {
    some i
    uri := input.cert.san.uri[i]
    startswith(uri, "urn:iotwidgits:fleet:")
    f := substring(uri, count("urn:iotwidgits:fleet:"), -1)
}

is_admin  { roles["admin"] }
is_reader { roles["reader"] }

# Partial "any known role" — the baseline for allowing connect.
has_any_role {
    some _ in roles
}

# ---- connect ----------------------------------------------------------

default connect := false

connect {
    input.cert.chain_ok
    input.cert.cn != ""
    has_any_role
    audit.log(sprintf("roles=%v fleets=%v cn=%v",
                      [roles, fleets, input.cert.cn]))
}

# ---- acl --------------------------------------------------------------

default acl := false

# Admin: ops/# full access.
acl {
    is_admin
    startswith(input.acl.topic, "ops/")
}

# Fleet: per-fleet subtree (read or write). Each fleet the cert carries
# contributes its own allow.
acl {
    some fleet in fleets
    startswith(input.acl.topic, sprintf("fleet/%s/", [fleet]))
}

# Reader: subscribe-only, broader read than fleet members get.
acl {
    is_reader
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "ops/")
}
acl {
    is_reader
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "fleet/")
}
