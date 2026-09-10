"""Real RSA leaf certificates/proofs, including original RFC 4055 SPKI bytes."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from connectcoin_p2c_tools.protocol import PROOF_VERSION, parse_proof

from .helpers import ProofFixture, make_valid_proof

RSAE_OID = bytes.fromhex("06092a864886f70d010101")
PSS_OID = bytes.fromhex("06092a864886f70d01010a")
MGF1_OID = bytes.fromhex("06092a864886f70d010108")
SHA256_OID = bytes.fromhex("0609608648016503040201")
SHA384_OID = bytes.fromhex("0609608648016503040202")


def der(tag: int, value: bytes) -> bytes:
    length = len(value)
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8 or 1, "big")
    encoded_length = (
        bytes([length]) if length < 128 else bytes([0x80 | len(length_bytes)]) + length_bytes
    )
    return bytes([tag]) + encoded_length + value


def _content(encoded: bytes) -> bytes:
    offset = 2 + (encoded[1] & 0x7F) if encoded[1] & 0x80 else 2
    return encoded[offset:]


def pss_parameters(
    *,
    hash_oid: bytes = SHA256_OID,
    mgf_hash_oid: bytes = SHA256_OID,
    minimum_salt: int | None = 32,
    trailer: int | None = None,
    null_hash_parameters: bool = True,
) -> bytes:
    null = b"\x05\x00" if null_hash_parameters else b""
    fields = der(0xA0, der(0x30, hash_oid + null)) + der(
        0xA1, der(0x30, MGF1_OID + der(0x30, mgf_hash_oid + null))
    )
    if minimum_salt is not None and minimum_salt != 20:
        integer = minimum_salt.to_bytes(1, "big", signed=True)
        fields += der(0xA2, der(0x02, integer))
    if trailer is not None:
        fields += der(0xA3, der(0x02, trailer.to_bytes(1, "big")))
    return der(0x30, fields)


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def make_rsa_proof(
    *,
    scheme: int = 0x0804,
    mask: int = 7,
    pss_spki: bool = False,
    parameters: bytes = b"",
    key_size: int = 2048,
    signature_salt: int = 32,
    signature_mgf: hashes.HashAlgorithm | None = None,
) -> ProofFixture:
    original = make_valid_proof()
    envelope = original.envelope
    parsed = parse_proof(envelope.proof, envelope.domain, envelope.challenge)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSA proof test root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(10)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, None, None), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), False)
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, envelope.domain)]))
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(11)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(envelope.domain)]), False)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, None, None), True
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    if pss_spki:
        old_spki = leaf_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        old_algorithm = der(0x30, RSAE_OID + b"\x05\x00")
        assert _content(old_spki).startswith(old_algorithm)
        new_algorithm = der(0x30, PSS_OID + parameters)
        new_spki = der(0x30, new_algorithm + _content(old_spki)[len(old_algorithm) :])
        old_tbs = _content(leaf.tbs_certificate_bytes)
        assert old_tbs.count(old_spki) == 1
        tbs = der(0x30, old_tbs.replace(old_spki, new_spki))
        issuer_signature = root_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        # Certificate signing algorithm remains ECDSA. Only leaf SPKI is PSS.
        leaf_der = der(
            0x30,
            tbs + bytes.fromhex("300a06082a8648ce3d040302") + der(0x03, b"\x00" + issuer_signature),
        )
    old_signatures = bytes.fromhex("000d000400020403")
    new_signatures = bytes.fromhex("000d00040002") + scheme.to_bytes(2, "big")
    assert parsed.client_hello.count(old_signatures) == 1
    client_hello = parsed.client_hello.replace(old_signatures, new_signatures)
    certificate_entry = len(leaf_der).to_bytes(3, "big") + leaf_der + b"\x00\x00"
    certificate = _handshake(
        11, b"\x00" + len(certificate_entry).to_bytes(3, "big") + certificate_entry
    )
    transcript = client_hello + parsed.server_hello + parsed.encrypted_extensions + certificate
    message = (
        b"\x20" * 64
        + b"TLS 1.3, server CertificateVerify\x00"
        + hashlib.sha256(transcript).digest()
    )
    signature = leaf_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(signature_mgf or hashes.SHA256()), salt_length=signature_salt),
        hashes.SHA256(),
    )
    certificate_verify = _handshake(
        15, scheme.to_bytes(2, "big") + len(signature).to_bytes(2, "big") + signature
    )
    proof = bytes([PROOF_VERSION]) + transcript + certificate_verify
    return ProofFixture(
        envelope=replace(envelope, proof=proof, signature_algorithms_mask=mask),
        roots_pem=root.public_bytes(serialization.Encoding.PEM),
    )
