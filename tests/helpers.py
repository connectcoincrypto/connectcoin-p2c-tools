from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.hashes import claim_challenge


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def _extension(extension_type: int, value: bytes) -> bytes:
    return _u16(extension_type) + _u16(len(value)) + value


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + _u24(len(body)) + body


@dataclass(frozen=True, slots=True)
class ProofFixture:
    envelope: ConnectionProof
    roots_pem: bytes


def make_valid_proof() -> ProofFixture:
    domain = "example.com"
    txid = "dc9023857775b489145e2169d642928ba0bdf188c3e6ab90699f239f0df6a1f1"
    challenge = claim_challenge(txid, 0)

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "P2C test root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)

    sni_name = b"\x00" + _u16(len(domain)) + domain.encode("ascii")
    client_extensions = b"".join(
        (
            _extension(0, _u16(len(sni_name)) + sni_name),
            _extension(43, b"\x02\x03\x04"),
            _extension(13, b"\x00\x02\x04\x03"),
            _extension(51, _u16(36) + b"\x00\x1d\x00\x20" + b"\x01" * 32),
        )
    )
    client_body = (
        b"\x03\x03"
        + challenge
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + _u16(len(client_extensions))
        + client_extensions
    )
    client_hello = _handshake(1, client_body)

    server_extensions = _extension(43, b"\x03\x04") + _extension(
        51, b"\x00\x1d\x00\x20" + b"\x02" * 32
    )
    server_body = (
        b"\x03\x03"
        + b"\x03" * 32
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + _u16(len(server_extensions))
        + server_extensions
    )
    server_hello = _handshake(2, server_body)
    encrypted_extensions = _handshake(8, b"\x00\x00")
    certificate_entry = _u24(len(leaf_der)) + leaf_der + b"\x00\x00"
    certificate = _handshake(11, b"\x00" + _u24(len(certificate_entry)) + certificate_entry)
    transcript_hash = hashlib.sha256(
        client_hello + server_hello + encrypted_extensions + certificate
    ).digest()
    signed = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" + transcript_hash
    signature = leaf_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    certificate_verify = _handshake(15, b"\x04\x03" + _u16(len(signature)) + signature)
    proof = b"\x01" + b"".join(
        (client_hello, server_hello, encrypted_extensions, certificate, certificate_verify)
    )
    envelope = ConnectionProof(
        domain=domain,
        txid=txid,
        input_index=0,
        connection_work_target="f" * 64,
        root_certificates_version=1,
        validation_time=1_800_000_000,
        proof=proof,
    )
    return ProofFixture(
        envelope=envelope,
        roots_pem=root.public_bytes(serialization.Encoding.PEM),
    )
