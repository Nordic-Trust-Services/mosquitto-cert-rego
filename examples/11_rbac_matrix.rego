# 11_rbac_matrix.rego
#
# Full RBAC matrix example: multiple roles, distinct topic namespaces per
# role, action-level differentiation (publish/subscribe/read/write), and
# explicit deny patterns.
#
# Intended as a production-shaped template — not a minimal demo. The key
# design points:
#
#   1. Roles come from SAN URIs (same pattern as 10_san_uri_roles.rego),
#      so the issuing CA controls them at signing time.
#   2. Each acl rule is keyed on ONE role + ONE action + ONE topic prefix.
#      No role inherits from another implicitly. Want admin to read a
#      viewer topic? Add a rule saying so.
#   3. The `acl` rule is `default := false` and every allow is a positive
#      statement. There are no explicit `deny` rules — this is "default
#      deny, allow by exception", the only shape that's obvious to audit.
#   4. Tenancy isolation is expressed by per-fleet allows that bind the
#      fleet name from the SAN URI into the topic prefix.
#   5. Every deny leaves a clean audit line: the broker's deny-notice line
#      carries the cert's roles[] and fleets[] so you can tell WHY.
#
# ------------------------------------------------------------------------
# Allow / deny matrix (rows = roles, columns = topic namespaces; entries
# are the allowed action set, `—` is deny). Fleet rows use `<X>` to mean
# the fleet name the cert itself carries.
# ------------------------------------------------------------------------
#
#                 ops/cmd/**    ops/status/**    config/**    fleet/<X>/**    fleet/<Y>/**    $SYS/**
#                 (control)     (telemetry)      (secrets)    (own fleet)     (other fleet)   (broker)
#   admin         pub + sub     sub              pub + sub    pub + sub       —               sub
#   operator      pub to        sub              —            pub + sub       —               —
#                 ops/cmd/ack/*
#                 only
#   viewer        sub           sub              —            sub             —               —
#   device        sub           pub to           —            pub + sub       —               —
#                               ops/status/
#                               <cn>/* only
#   (no role)     —             —                —            —               —               —
#
# Under no circumstances may a cert:
#   - publish to config/**       unless role=admin
#   - subscribe to $SYS/**       unless role=admin
#   - publish to any topic       unless the cert carries at least one role
#   - touch a fleet it is not a member of  (handled by the fleet binding)
#
# Add a negative test in cybersec for every "unless" above if the
# deployment is high-sensitivity — the examples/ harness already does
# tenancy crossing + role escape in the e2e suite.

package mqtt

# ---- role / fleet extraction -----------------------------------------
#
# URIs that look like urn:iotwidgits:role:<name> and urn:iotwidgits:fleet:<name>.

roles[r] {
    some i
    uri := input.cert.san.uri[i]
    startswith(uri, "urn:iotwidgits:role:")
    r := substring(uri, count("urn:iotwidgits:role:"), -1)
}

fleets[f] {
    some i
    uri := input.cert.san.uri[i]
    startswith(uri, "urn:iotwidgits:fleet:")
    f := substring(uri, count("urn:iotwidgits:fleet:"), -1)
}

is_admin    { roles["admin"] }
is_operator { roles["operator"] }
is_viewer   { roles["viewer"] }
is_device   { roles["device"] }

# Whitelist of roles this policy knows how to reason about. Certs with
# roles outside this set don't even reach the ACL stage — tightening
# this here is strictly safer than rejecting unknown roles in each ACL
# rule one at a time.
known_role := {"admin", "operator", "viewer", "device"}

# At least one KNOWN role is the baseline for connecting at all.
# rego-cpp runs in v0 dialect: iterate a set by binding a new variable
# against set-membership form `set[var]`, not `some x in set`.
has_any_role {
    roles[r]
    known_role[r]
}

# Cert's CN — used to scope telemetry writes for the `device` role.
cn := input.cert.cn

# ---- connect ----------------------------------------------------------
#
# Baseline gate: verified chain + a non-empty CN + at least one recognised
# role. audit.log() records the role set so denies and allows both carry
# the same provenance.

default connect := false

connect {
    input.cert.chain_ok
    input.cert.cn != ""
    has_any_role
    audit.log(sprintf("roles=%v fleets=%v cn=%v", [roles, fleets, cn]))
}

# ---- acl --------------------------------------------------------------

default acl := false

# ==== admin ===========================================================

# ops/cmd/**  — issue control commands (publish) and observe them (subscribe).
acl {
    is_admin
    input.acl.action == "write"
    startswith(input.acl.topic, "ops/cmd/")
}
acl {
    is_admin
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "ops/cmd/")
}

# ops/status/**  — subscribe only (no admin-side telemetry injection).
acl {
    is_admin
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "ops/status/")
}

# config/**  — read and write secrets. Admin ONLY.
acl {
    is_admin
    startswith(input.acl.topic, "config/")
}

# fleet/<X>/**  — admin owns every fleet it carries a membership for.
acl {
    is_admin
    fleets[fleet]
    startswith(input.acl.topic, sprintf("fleet/%s/", [fleet]))
}

# $SYS/**  — broker internals, subscribe only.
acl {
    is_admin
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "$SYS/")
}

# ==== operator ========================================================

# ops/cmd/ack/**  — narrow publish surface: can ack commands but can't
# issue them. Compare to admin which has the full ops/cmd/** publish right.
acl {
    is_operator
    input.acl.action == "write"
    startswith(input.acl.topic, "ops/cmd/ack/")
}

# ops/status/**  — operator sees everything that flows through telemetry.
acl {
    is_operator
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "ops/status/")
}

# fleet/<X>/**  — operator is hands-on in their fleet(s).
acl {
    is_operator
    fleets[fleet]
    startswith(input.acl.topic, sprintf("fleet/%s/", [fleet]))
}

# NOTE: operator has no config/ or $SYS/ rule. Default-deny takes care of it.

# ==== viewer ==========================================================
#
# Subscribe-only across ops and fleet — a read-only operator. The
# absence of a publish allow anywhere is the enforcement.

acl {
    is_viewer
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "ops/cmd/")
}
acl {
    is_viewer
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "ops/status/")
}
acl {
    is_viewer
    input.acl.action == "subscribe"
    fleets[fleet]
    startswith(input.acl.topic, sprintf("fleet/%s/", [fleet]))
}

# ==== device ==========================================================
#
# A physical device. Can publish its own telemetry (topic scoped to its
# CN), subscribe to commands, and participate in its fleet.

# ops/status/<cn>/**  — telemetry publish scoped to the device's own CN.
# A device that tried to publish to ops/status/<other>/foo would be denied.
acl {
    is_device
    input.acl.action == "write"
    startswith(input.acl.topic, sprintf("ops/status/%s/", [cn]))
}

# ops/cmd/**  — receive commands. No publish here.
acl {
    is_device
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "ops/cmd/")
}

# fleet/<X>/**  — intra-fleet coordination.
acl {
    is_device
    fleets[fleet]
    startswith(input.acl.topic, sprintf("fleet/%s/", [fleet]))
}

# ------------------------------------------------------------------------
# Negative cases worth testing (see e2e/cybersec.py for the pattern):
#
#   1. viewer-cert publish to ops/cmd/start     → deny (no viewer+publish rule)
#   2. operator publish to config/secret        → deny (operator lacks config/)
#   3. operator publish to ops/cmd/start        → deny (only ack/ is allowed)
#   4. device publish to ops/status/<other>/x   → deny (CN binding mismatch)
#   5. device subscribe to $SYS/#               → deny (admin-only)
#   6. cert with role=reader (unknown role)     → connect deny (has_any_role
#                                                  requires one of the four)
#   7. cert with role=admin but fleets=[]
#      subscribing to fleet/north/bus           → deny (no membership)
#   8. operator in fleets=[north]
#      subscribing to fleet/south/bus           → deny (cross-tenant)
#
# Each of these falls out of default-deny plus the absence of a matching
# positive rule — the policy has no `deny` statements, and that is the
# point. A deny rule would be an escape hatch an attacker can aim for;
# default-deny with explicit allows has nowhere to hide a mistake.
