# 07_crl_in_rego.rego
#
# CRL revocation check driven by the policy. Same shape as ocsp.check(),
# but against CRLs fetched from the cert's crlDistributionPoints.
#
# Return shape (after json.unmarshal):
#   [{"depth":0, "subject_dn":"...", "status":"good", "cached":true, "error":null}, ...]
#
# status: good / revoked / expired_crl / unknown / error / skipped_root
#         / no_dp / bad_sig
#
# The plugin caches every fetched CRL by URL (and every OCSP response by
# CertID) up to the configured TTL, clamped by nextUpdate. Repeated
# connects warm the cache; subsequent evaluations are constant-time.

package mqtt

crl_statuses  := json.unmarshal(crl.check())
ocsp_statuses := json.unmarshal(ocsp.check())

# Any explicit "revoked" kills, from either source.
any_revoked { some i; crl_statuses[i].status == "revoked" }
any_revoked { some i; ocsp_statuses[i].status == "revoked" }

# Stricter: also reject if either source reports anything other than
# "good" or "skipped_root" for non-root certs.
is_good(s) { s == "good" }
is_good(s) { s == "skipped_root" }

all_crl_good  { not crl_any_bad }
crl_any_bad   { some i; not is_good(crl_statuses[i].status) }
all_ocsp_good { not ocsp_any_bad }
ocsp_any_bad  { some i; not is_good(ocsp_statuses[i].status) }

default connect := false
default acl := false

# Belt-and-braces: reject on any revocation signal, require clean OCSP
# and clean CRL before admitting a connection.
connect {
    input.cert.chain_ok
    input.cert.cn != ""
    not any_revoked
    all_ocsp_good
    all_crl_good
}

acl {
    startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn]))
}
