#!/usr/bin/env python3
"""
Build the CRL fixture set:
  pki/crl_good_alice.crt/.key       — CN=crl-good-alice with crlDistributionPoints
                                      → http://127.0.0.1:18889/intermediate_a.crl
  pki/crl_revoked_alice.crt/.key    — CN=crl-revoked-alice, same CRL DP URL
  pki/intermediate_a.crl            — CRL signed by intermediate_a, listing
                                      crl_revoked_alice's serial as revoked

Re-runnable.
"""
from __future__ import annotations
import datetime
import pathlib
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

PKI = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("e2e/pki")
CRL_URL = "http://127.0.0.1:18889/intermediate_a.crl"


def save_key(key, path: pathlib.Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def save_cert(cert, path: pathlib.Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)


def main() -> None:
    ca_cert = x509.load_pem_x509_certificate((PKI/"intermediate_a.crt").read_bytes())
    ca_key  = serialization.load_pem_private_key((PKI/"intermediate_a.key").read_bytes(), password=None)

    def build_client(cn: str, out: str) -> tuple[x509.Certificate, int]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        save_key(key, PKI/f"{out}.key")
        serial = x509.random_serial_number()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "example"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2034, 1, 1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(CRL_URL)],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    ),
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        save_cert(cert, PKI/f"{out}.crt")
        return cert, serial

    good_cert, good_serial = build_client("crl-good-alice", "crl_good_alice")
    revoked_cert, revoked_serial = build_client("crl-revoked-alice", "crl_revoked_alice")

    # Build a CRL signed by intermediate_a, listing the revoked cert.
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(datetime.datetime(2024, 1, 1))
        .next_update(datetime.datetime(2034, 1, 1))
    )
    revoked_entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(revoked_serial)
        .revocation_date(datetime.datetime(2025, 6, 1, 12, 0, 0))
        .build()
    )
    builder = builder.add_revoked_certificate(revoked_entry)
    crl = builder.sign(ca_key, hashes.SHA256())

    crl_path = PKI/"intermediate_a.crl"
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.DER))
    crl_path.chmod(0o644)

    print(f"wrote CRL fixtures to {PKI}")
    print(f"  good_serial    = {good_serial:X}")
    print(f"  revoked_serial = {revoked_serial:X}")
    print(f"  crl bytes      = {crl_path.stat().st_size}")


if __name__ == "__main__":
    main()
