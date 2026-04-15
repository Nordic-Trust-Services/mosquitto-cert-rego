#!/usr/bin/env python3
"""
Build the OCSP fixture set:
  pki/ocsp_signer.crt/.key              — delegated OCSP responder, EKU=OCSPSigning,
                                          signed by intermediate_a
  pki/ocsp_good_alice.crt/.key          — CN=ocsp-good-alice, AIA OCSP URL
                                          http://127.0.0.1:18888
  pki/ocsp_revoked_alice.crt/.key       — CN=ocsp-revoked-alice, same AIA URL
  pki/ocsp_index.txt                    — openssl CA-format index with
                                          the revoked cert listed as R and
                                          the good cert listed as V
  pki/ocsp_index.txt.attr               — required companion file for
                                          openssl's index format

Re-runnable: exits early if all artefacts exist.
"""
from __future__ import annotations
import datetime
import pathlib
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID


PKI = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("e2e/pki")
OCSP_URL = "http://127.0.0.1:18888"


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


def build_subject(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "example"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def main() -> None:
    ca_cert = x509.load_pem_x509_certificate((PKI/"intermediate_a.crt").read_bytes())
    ca_key  = serialization.load_pem_private_key((PKI/"intermediate_a.key").read_bytes(), password=None)

    # -------- OCSP delegated signer -----------------------------------------
    signer_path = PKI/"ocsp_signer.crt"
    if not signer_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        save_key(key, PKI/"ocsp_signer.key")
        cert = (
            x509.CertificateBuilder()
            .subject_name(build_subject("Acme OCSP Responder"))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2034, 1, 1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False
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
        save_cert(cert, signer_path)

    # -------- Client certs with AIA OCSP URL -------------------------------
    def build_client(cn: str, out_name: str) -> tuple[x509.Certificate, int]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        save_key(key, PKI/f"{out_name}.key")
        serial = x509.random_serial_number()
        cert = (
            x509.CertificateBuilder()
            .subject_name(build_subject(cn))
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
            .add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(OCSP_URL),
                    ),
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        save_cert(cert, PKI/f"{out_name}.crt")
        return cert, serial

    good_cert, good_serial = build_client("ocsp-good-alice", "ocsp_good_alice")
    revoked_cert, revoked_serial = build_client("ocsp-revoked-alice", "ocsp_revoked_alice")

    # -------- openssl index.txt for the responder --------------------------
    # Format per openssl: one line per cert, tab-separated:
    #   flag | notAfter (YYMMDDHHMMSSZ) | revoked_at (YYMMDDHHMMSSZ or empty) | serial (hex, UPPER) | filename | subject_dn
    def fmt_time(dt: datetime.datetime) -> str:
        return dt.strftime("%y%m%d%H%M%SZ")

    def fmt_serial(n: int) -> str:
        return f"{n:X}".zfill(2)  # openssl tolerates any length hex

    revoked_at = datetime.datetime(2025, 6, 1, 12, 0, 0)

    def index_line(cert: x509.Certificate, flag: str, revoked: str = "") -> str:
        subject = "/".join(
            f"{attr.oid._name}={attr.value}" for attr in cert.subject
        ).replace(" ", "_")
        return "\t".join([
            flag,
            fmt_time(cert.not_valid_after),
            revoked,
            fmt_serial(cert.serial_number),
            "unknown",
            f"/{subject}",
        ]) + "\n"

    idx = PKI/"ocsp_index.txt"
    idx.write_text(
        index_line(good_cert, "V") +
        index_line(revoked_cert, "R", fmt_time(revoked_at))
    )
    (PKI/"ocsp_index.txt.attr").write_text("unique_subject = no\n")

    print(f"wrote OCSP fixtures to {PKI}")
    print(f"  good_serial    = {fmt_serial(good_serial)}")
    print(f"  revoked_serial = {fmt_serial(revoked_serial)}")


if __name__ == "__main__":
    main()
