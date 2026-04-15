# 03_ldap_group_gate.rego
#
# Connection gated on LDAP group membership, with a structural chain
# integrity check layered on top.
#
# After the group check, the client is scoped to its own devices/<cn>/
# subtree — same as example 02.

package mqtt

ldap_url          := "ldaps://ldap.example.com"
ldap_bind_dn      := "cn=mqtt-readonly,ou=services,dc=example,dc=com"
ldap_bind_pw      := "changeme"
allowed_group_dn  := "cn=mqtt-clients,ou=groups,dc=example,dc=com"
people_base_dn    := "ou=people,dc=example,dc=com"

user_dn := sprintf("uid=%s,%s", [input.cert.cn, people_base_dn])

in_allowed_group {
    ldap.is_member(ldap_url, ldap_bind_dn, ldap_bind_pw, allowed_group_dn, user_dn)
}

# Structural chain integrity: every cert's issuer_dn matches the next
# cert's subject_dn. The plugin has already cryptographically verified
# signatures — this is a policy-level assertion that makes the expected
# chain shape explicit and catches upstream drift.
chain_linked { not chain_link_broken }

chain_link_broken {
    some i
    i < count(input.cert.chain) - 1
    input.cert.chain[i].issuer_dn != input.cert.chain[i + 1].subject_dn
}

default connect := false
default acl := false

connect {
    input.cert.chain_ok
    input.cert.cn != ""
    in_allowed_group
    chain_linked
}

acl {
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}

acl { input.acl.action == "unsubscribe" }
