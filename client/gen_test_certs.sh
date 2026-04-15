#!/usr/bin/env bash
# Copyright (c) 2026 Cedalo Ltd
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#
# Generate a small test PKI for exercising the mosquitto cert-rego plugin.
#
# USAGE:
#   ./gen_test_certs.sh [PKI_DIR]              # single root, 2 clients
#   MULTI_ROOT=1 ./gen_test_certs.sh [PKI_DIR] # two roots, clients under each
#
# SINGLE-ROOT OUTPUT (default):
#   pki/root.crt          — self-signed root CA
#   pki/intermediate.crt  — intermediate CA signed by the root
#   pki/server.crt        — mosquitto broker server cert
#   pki/bundle.pem        — root + intermediate, for cafile= and ca_file
#   pki/alice.crt         — CN=alice (allowed test client)
#   pki/bob.crt           — CN=bob   (deny test)
#   + matching .key files (mode 0600)
#
# MULTI-ROOT OUTPUT (MULTI_ROOT=1):
#   pki/root_a.crt        — "operator" root
#   pki/root_b.crt        — "device" root
#   pki/intermediate_a.crt, intermediate_b.crt
#   pki/bundle_a.pem      — root_a + intermediate_a
#   pki/bundle_b.pem      — root_b + intermediate_b
#   pki/bundle_all.pem    — both (use this as cert_rego_ca_file)
#   pki/server.crt        — signed under root_a (for listener TLS)
#   pki/operator_alice.crt — CN=alice under root_a
#   pki/operator_bob.crt   — CN=bob under root_a
#   pki/device_01.crt      — CN=device-01 under root_b
#   pki/device_02.crt      — CN=device-02 under root_b
#
# The two-root PKI lets you exercise `input.cert.trust_anchor` dispatch in
# Rego — see examples/04_multi_root_ca.rego.
#
# Every cert is RSA 2048, SHA-256, 10-year validity. Test material only.

set -euo pipefail

OUT_DIR="${1:-pki}"
DAYS="${CERT_DAYS:-3650}"
HOST="${SERVER_HOST:-localhost}"
MULTI="${MULTI_ROOT:-0}"

mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

echo "==> writing PKI to $(pwd) (multi_root=${MULTI})"


# ---- openssl config snippets ---------------------------------------------

cat > openssl.cnf <<'CNF'
[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = req_dn

[ req_dn ]
CN = overridden-per-cert

[ v3_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash

[ v3_intermediate ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer

[ v3_server ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName         = @server_san

[ server_san ]
DNS.1 = __HOST__
DNS.2 = localhost
IP.1  = 127.0.0.1

[ v3_client ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
CNF

sed -i "s/__HOST__/${HOST}/" openssl.cnf


# ---- helpers -------------------------------------------------------------

# gen_root LABEL DESCRIPTION
gen_root() {
    local label="$1"
    local desc="$2"
    echo "==> root CA ${label} (${desc})"
    openssl genrsa -out "${label}.key" 2048 2>/dev/null
    openssl req -x509 -new -key "${label}.key" -sha256 -days "${DAYS}" \
        -out "${label}.crt" \
        -subj "/CN=${desc}/O=example/C=US" \
        -extensions v3_ca -config openssl.cnf
}

# gen_intermediate LABEL UNDER_ROOT DESCRIPTION
gen_intermediate() {
    local label="$1"
    local root="$2"
    local desc="$3"
    echo "==> intermediate ${label} (${desc}) under ${root}"
    openssl genrsa -out "${label}.key" 2048 2>/dev/null
    openssl req -new -key "${label}.key" -sha256 \
        -out "${label}.csr" \
        -subj "/CN=${desc}/O=example/C=US"
    openssl x509 -req -in "${label}.csr" \
        -CA "${root}.crt" -CAkey "${root}.key" -CAcreateserial \
        -days "${DAYS}" -sha256 \
        -extensions v3_intermediate -extfile openssl.cnf \
        -out "${label}.crt" 2>/dev/null
}

# gen_server LABEL UNDER_INTERMEDIATE CN
gen_server() {
    local label="$1"
    local intm="$2"
    local cn="$3"
    echo "==> server cert ${label} (CN=${cn}) under ${intm}"
    openssl genrsa -out "${label}.key" 2048 2>/dev/null
    openssl req -new -key "${label}.key" -sha256 \
        -out "${label}.csr" \
        -subj "/CN=${cn}/O=example/C=US"
    openssl x509 -req -in "${label}.csr" \
        -CA "${intm}.crt" -CAkey "${intm}.key" -CAcreateserial \
        -days "${DAYS}" -sha256 \
        -extensions v3_server -extfile openssl.cnf \
        -out "${label}.crt" 2>/dev/null
}

# gen_client LABEL UNDER_INTERMEDIATE CN
gen_client() {
    local label="$1"
    local intm="$2"
    local cn="$3"
    echo "==> client cert ${label} (CN=${cn}) under ${intm}"
    openssl genrsa -out "${label}.key" 2048 2>/dev/null
    openssl req -new -key "${label}.key" -sha256 \
        -out "${label}.csr" \
        -subj "/CN=${cn}/O=example/C=US"
    openssl x509 -req -in "${label}.csr" \
        -CA "${intm}.crt" -CAkey "${intm}.key" -CAcreateserial \
        -days "${DAYS}" -sha256 \
        -extensions v3_client -extfile openssl.cnf \
        -out "${label}.crt" 2>/dev/null
}


# ---- single-root path ----------------------------------------------------

if [ "${MULTI}" = "0" ]; then
    gen_root         root "cert-auth test root"
    gen_intermediate intermediate root "cert-auth test intermediate"
    gen_server       server       intermediate "${HOST}"
    gen_client       alice        intermediate "alice"
    gen_client       bob          intermediate "bob"

    cat intermediate.crt root.crt > bundle.pem

    rm -f ./*.csr ./*.srl
    chmod 600 ./*.key
    chmod 644 ./*.crt ./bundle.pem

    echo
    echo "==> single-root PKI ready"
    echo "listener cafile: $(pwd)/bundle.pem"
    echo "plugin_opt_cert_rego_ca_file: $(pwd)/bundle.pem"
    exit 0
fi


# ---- multi-root path -----------------------------------------------------

gen_root         root_a         "operator CA"
gen_root         root_b         "device CA"
gen_intermediate intermediate_a root_a "operator intermediate"
gen_intermediate intermediate_b root_b "device intermediate"

# Server cert is issued under root_a (arbitrary — either would do).
gen_server       server         intermediate_a "${HOST}"

# Operators under root_a, devices under root_b.
gen_client       operator_alice intermediate_a "alice"
gen_client       operator_bob   intermediate_a "bob"
gen_client       device_01      intermediate_b "device-01"
gen_client       device_02      intermediate_b "device-02"

# Per-root bundles (intermediate + root). Useful for selective trust.
cat intermediate_a.crt root_a.crt > bundle_a.pem
cat intermediate_b.crt root_b.crt > bundle_b.pem

# Combined bundle: use this as the plugin's cert_rego_ca_file to make the
# plugin trust certs from BOTH CAs. The Rego policy can then dispatch on
# which root the chain anchored to via input.cert.trust_anchor.
cat bundle_a.pem bundle_b.pem > bundle_all.pem

rm -f ./*.csr ./*.srl
chmod 600 ./*.key
chmod 644 ./*.crt ./bundle_*.pem

# Print the fingerprints — paste them into 04_multi_root_ca.rego.
root_a_fp=$(openssl x509 -in root_a.crt -noout -fingerprint -sha256 \
    | tr 'A-F' 'a-f' | tr -d ':' | sed 's/.*=//')
root_b_fp=$(openssl x509 -in root_b.crt -noout -fingerprint -sha256 \
    | tr 'A-F' 'a-f' | tr -d ':' | sed 's/.*=//')

echo
echo "==> multi-root PKI ready"
echo
echo "listener cafile (trusts both roots):"
echo "  $(pwd)/bundle_all.pem"
echo
echo "plugin_opt_cert_rego_ca_file (comma-separated OR single bundle):"
echo "  $(pwd)/bundle_a.pem,$(pwd)/bundle_b.pem"
echo "  (equivalent to $(pwd)/bundle_all.pem)"
echo
echo "Root fingerprints for examples/04_multi_root_ca.rego:"
echo "  root_a_fp := \"${root_a_fp}\"    # operator CA"
echo "  root_b_fp := \"${root_b_fp}\"    # device CA"
