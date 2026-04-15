#!/usr/bin/env python3
# Mint an already-expired client cert signed by intermediate_a. Used by
# gen-negative-certs.sh because Ubuntu 22.04's openssl x509 -req lacks the
# -not_before/-not_after flags.
import sys, datetime, pathlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

pki = pathlib.Path(sys.argv[1])

ca_cert = x509.load_pem_x509_certificate((pki/"intermediate_a.crt").read_bytes())
ca_key  = serialization.load_pem_private_key((pki/"intermediate_a.key").read_bytes(), password=None)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
(pki/"expired_alice.key").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
)

subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "example"),
    x509.NameAttribute(NameOID.COMMON_NAME, "alice"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime(2020, 1, 1))
    .not_valid_after(datetime.datetime(2021, 1, 1))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    )
    .sign(ca_key, hashes.SHA256())
)
(pki/"expired_alice.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print("wrote expired_alice.{crt,key}")
