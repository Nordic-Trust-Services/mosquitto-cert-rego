# 08_chain_traversal.rego
#
# Overriding specific chain-verification failures.
#
# The plugin runs X509_verify_cert with a collecting verify callback —
# every per-cert error is surfaced to Rego, the plugin never auto-denies.
# Policies decide whether to accept, and which failure modes warrant an
# override.
#
# Rego input it relies on (per the input schema):
#
#   input.cert.chain_ok        — bool, true if every cert verified cleanly
#   input.cert.chain_errors[]  — deduplicated short codes across the
#                                whole chain ("expired", "not_yet_valid",
#                                "issuer_unknown", "bad_signature",
#                                "self_signed", "untrusted",
#                                "crl_expired", "revoked", "invalid_ca",
#                                "path_length_exceeded", "invalid_purpose",
#                                "chain_too_long", "akid_mismatch",
#                                "no_chain", "other")
#   input.cert.chain[]         — per-cert metadata, each entry carries
#                                verify_ok (bool) and errors[] (code+message)
#
# Policies have three legitimate postures:
#   1. clean_only     — accept only a fully-verified chain (default / safest)
#   2. selective      — accept specific named failures (e.g. expired intermediate)
#   3. cert-specific  — accept failures only on specific certs in the chain
#
# This example shows all three, built from the same input facts.

package mqtt

# ---- 1. clean baseline -------------------------------------------------

# The dead-simple case: require chain_ok. No override logic.
clean_chain { input.cert.chain_ok }

# ---- 2. selective override by short code ------------------------------

# Errors the policy tolerates chain-wide. Everything else denies.
# In a real deployment you'd time-box these with an external data.json
# ("we are in a 30-day grace window on root_a expiry") rather than
# baking them into the .rego source.
tolerable_chain_errors := {
    "expired",         # transitionally OK during root rotation
    "not_yet_valid",   # OK when a cert was issued with a future notBefore
}

# True if every error present in the chain is in the tolerable set.
chain_errors_only_tolerable {
    count(input.cert.chain_errors) > 0
    unexpected := {c |
        some i
        c := input.cert.chain_errors[i]
        not tolerable_chain_errors[c]
    }
    count(unexpected) == 0
}

selective_override_ok {
    chain_errors_only_tolerable
}

# ---- 3. override only on specific certs ------------------------------

# Stricter variant of 2: we allow "expired" — but ONLY on the issuing
# intermediate (depth 1), never on the leaf. An expired leaf always
# denies even if chain_errors says "expired" because the location
# matters.
#
# The fingerprint pins down which intermediate; by the time you accept
# this override you should have already decided which intermediate you
# trust despite its expiry.
transitional_intermediate_fps := {
    "REPLACE_WITH_EXPIRED_INTERMEDIATE_FP",
}

leaf_verify_ok { input.cert.chain[0].verify_ok }

# True if this specific intermediate is one we've decided to tolerate.
expected_expired_intermediate {
    input.cert.chain[1].verify_ok == false
    input.cert.chain[1].errors[_].code == "expired"
    transitional_intermediate_fps[input.cert.chain[1].fingerprint_sha256]
}

cert_specific_override_ok {
    leaf_verify_ok
    expected_expired_intermediate
    # Reject any OTHER error anywhere in the chain.
    every_other_cert_ok
}

every_other_cert_ok {
    not any_unexpected_failure
}

any_unexpected_failure {
    some i
    input.cert.chain[i].verify_ok == false
    i != 1    # intermediate we've already accepted
}

# ---- combined connect rule --------------------------------------------

default connect := false
default acl := false

connect {
    input.cert.cn != ""
    clean_chain
}

connect {
    input.cert.cn != ""
    selective_override_ok
}

connect {
    input.cert.cn != ""
    cert_specific_override_ok
}

acl {
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}
