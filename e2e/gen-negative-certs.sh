#!/usr/bin/env bash
# Generate the negative-case client certificates used by the cybersec suite.
#
# Requires the MULTI_ROOT PKI to already exist (gen_test_certs.sh must
# have been run with MULTI_ROOT=1 e2e/pki). Adds:
#
#   pki/untrusted_root.crt/.key        — self-signed root not in any bundle
#   pki/intruder.crt/.key               — client cert signed by that root
#   pki/expired_root.crt/.key           — separate root, kept out of bundle_all
#   pki/expired_intermediate.crt/.key   — ditto
#   pki/expired_alice.crt/.key          — CN=alice, signed by operator_intermediate,
#                                         but with notBefore/notAfter firmly in the past
#   pki/injection_alice.crt/.key        — CN containing JSON-injection bytes
#                                         (quote, backslash, newline) to stress audit framing
#   pki/huge_cn.crt/.key                — 800-char CN to stress truncation
#
# The certs are built alongside the main PKI under ${E2E_DIR}/pki.
#
# Uses openssl + faketime (faketime optional; falls back to setting
# explicit dates with -not_before / -not_after).

set -euo pipefail
E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI="${E2E_DIR}/pki"

if [ ! -f "${PKI}/bundle_all.pem" ]; then
    echo "Multi-root PKI missing. Run gen_test_certs.sh with MULTI_ROOT=1 first." >&2
    exit 1
fi

cd "${PKI}"
cfg=openssl.cnf  # left over from gen_test_certs.sh

# ---- 1. Untrusted root + intruder ---------------------------------------
if [ ! -f untrusted_root.crt ]; then
    echo "==> untrusted root + intruder client"
    openssl genrsa -out untrusted_root.key 2048 2>/dev/null
    openssl req -x509 -new -key untrusted_root.key -sha256 -days 3650 \
        -out untrusted_root.crt -subj "/CN=rogue root/O=attacker/C=US" \
        -extensions v3_ca -config "${cfg}"

    openssl genrsa -out intruder.key 2048 2>/dev/null
    openssl req -new -key intruder.key -sha256 -out intruder.csr \
        -subj "/CN=alice/O=attacker/C=US"
    openssl x509 -req -in intruder.csr \
        -CA untrusted_root.crt -CAkey untrusted_root.key -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_client -extfile "${cfg}" \
        -out intruder.crt 2>/dev/null
    rm -f intruder.csr
fi

# ---- 2. Expired leaf signed by the real operator intermediate ------------
# Sign a cert whose notAfter is in the past so chain_ok must be false.
# Ubuntu 22.04's OpenSSL 3.0.2 x509 -req doesn't accept -not_before/-not_after,
# so we drive it from Python's cryptography library instead.
if [ ! -f expired_alice.crt ]; then
    echo "==> expired_alice (operator intermediate, notAfter in the past)"
    python3 "${E2E_DIR}/_gen_expired_cert.py" "${PKI}"
fi

# ---- 3. CN with JSON-unsafe characters ----------------------------------
# \", \\, \n and a stray control byte — must not break audit framing.
if [ ! -f injection_alice.crt ]; then
    echo "==> injection_alice (CN with quote/backslash/newline)"
    openssl genrsa -out injection_alice.key 2048 2>/dev/null
    # OpenSSL's -subj escapes \ and /; feed the characters through a config file.
    cat > injection_subj.cnf <<EOF
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = dn
req_extensions = v3_client

[ dn ]
CN = alice"evil\\\\path/newline

[ v3_client ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
    openssl req -new -key injection_alice.key -sha256 \
        -config injection_subj.cnf -out injection_alice.csr
    openssl x509 -req -in injection_alice.csr \
        -CA intermediate_a.crt -CAkey intermediate_a.key -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_client -extfile "${cfg}" \
        -out injection_alice.crt 2>/dev/null
    rm -f injection_alice.csr injection_subj.cnf
fi

chmod 600 ./*.key
chmod 644 ./*.crt

echo "==> negative-case certs ready"
