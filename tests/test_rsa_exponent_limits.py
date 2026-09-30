"""Offline, self-contained regressions for Core's certificate RSA exponent bound."""

from __future__ import annotations

import hashlib
import socket
from dataclasses import replace
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.errors import ProofFormatError, ProofVerificationError
from connectcoin_p2c_tools.protocol import parse_certificate_message, parse_proof
from connectcoin_p2c_tools.tls13 import (
    CONTENT_APPLICATION_DATA,
    CONTENT_HANDSHAKE,
    Endpoint,
    TLSGenerationError,
    build_client_hello,
    capture_tls13_proof,
)
from connectcoin_p2c_tools.verify import (
    MAX_RSA_PUBLIC_EXPONENT_BITS,
    _check_rsa_public_exponents,
    _verify_certificate_signature,
    validate_certificate_message,
    validate_root_bundle,
    verify_connection_proof,
)

DER = serialization.Encoding.DER
PEM = serialization.Encoding.PEM
LIMIT_ERROR = "P2C certificate RSA public exponent exceeds 64 bits"
# Public, deterministic test keys; never used outside these fixtures.
ROOT_KEY = ec.derive_private_key(101, ec.SECP256R1())
LEAF_KEY = ec.derive_private_key(102, ec.SECP256R1())


def _der(tag: int, data: bytes) -> bytes:
    size = len(data)
    encoded = size.to_bytes(max(1, (size.bit_length() + 7) // 8), "big")
    length = bytes([size]) if size < 128 else bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + data


def _content(encoded: bytes) -> bytes:
    return encoded[2 + (encoded[1] & 0x7F) :] if encoded[1] & 0x80 else encoded[2:]


@lru_cache(maxsize=2)
def _modulus(bits: int) -> int:
    return rsa.generate_private_key(65537, bits).public_key().public_numbers().n


def _certificate(
    subject: str, issuer: str, public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey, *, ca: bool
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(public_key)
        .serial_number(20 if ca else 21)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, None, None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ROOT_KEY.public_key()), False
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]), False
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
        )
    return builder.sign(ROOT_KEY, hashes.SHA256())


def _rsa_certificate(exponent: int, *, pss: bool = False, bits: int = 2048) -> x509.Certificate:
    public = rsa.RSAPublicNumbers(exponent, _modulus(bits)).public_key()
    cert = _certificate("RSA test CA", "EC test root", public, ca=True)
    if not pss:
        return cert
    # Keep id-RSASSA-PSS in original SPKI, without relying on reserialization of
    # a generic RSAPublicKey. The CA signature becomes invalid intentionally.
    spki = public.public_bytes(DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    rsa_algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    assert _content(spki).startswith(rsa_algorithm)
    pss_algorithm = bytes.fromhex("300b06092a864886f70d01010a")
    replacement = _der(0x30, pss_algorithm + _content(spki)[len(rsa_algorithm) :])
    tbs_body = _content(cert.tbs_certificate_bytes)
    assert tbs_body.count(spki) == 1
    tbs = _der(0x30, tbs_body.replace(spki, replacement))
    result = _der(
        0x30, tbs + bytes.fromhex("300a06082a8648ce3d040302") + _der(3, b"\x00" + cert.signature)
    )
    return x509.load_der_x509_certificate(result)


def _handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def _certificate_message(certificates: list[x509.Certificate]) -> bytes:
    entries = b"".join(
        len(cert.public_bytes(DER)).to_bytes(3, "big") + cert.public_bytes(DER) + b"\x00\x00"
        for cert in certificates
    )
    return _handshake(11, b"\x00" + len(entries).to_bytes(3, "big") + entries)


def _server_hello(session: bytes, public: bytes = b"\x02" * 32) -> bytes:
    extensions = bytes.fromhex("002b0002030400330024001d0020") + public
    return _handshake(
        2,
        b"\x03\x03"
        + b"\x03" * 32
        + bytes([len(session)])
        + session
        + b"\x13\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions,
    )


def _proof(certificates: list[x509.Certificate]) -> ConnectionProof:
    context = ConnectionProof(
        domain="example.com",
        txid="11" * 32,
        input_index=0,
        connection_work_target="f" * 64,
        root_certificates_version=1,
        signature_algorithms_mask=1,
        validation_time=1_800_000_000,
        proof=b"",
    )
    session = b"test"
    hello = build_client_hello(
        "example.com", context.challenge, b"\x01" * 32, session, signature_algorithms_mask=1
    )
    transcript = (
        hello
        + _server_hello(session)
        + _handshake(8, b"\x00\x00")
        + _certificate_message(certificates)
    )
    signed = (
        b"\x20" * 64
        + b"TLS 1.3, server CertificateVerify\x00"
        + hashlib.sha256(transcript).digest()
    )
    signature = LEAF_KEY.sign(signed, ec.ECDSA(hashes.SHA256()))
    proof = (
        b"\x02"
        + transcript
        + _handshake(15, b"\x04\x03" + len(signature).to_bytes(2, "big") + signature)
    )
    return replace(context, proof=proof)


def _ec_identity() -> tuple[x509.Certificate, x509.Certificate]:
    root = _certificate("EC test root", "EC test root", ROOT_KEY.public_key(), ca=True)
    leaf = _certificate("example.com", "EC test root", LEAF_KEY.public_key(), ca=False)
    return root, leaf


@pytest.mark.parametrize("pss", [False, True], ids=["rsae", "pss"])
@pytest.mark.parametrize("bits", [1024, 2048])
@pytest.mark.parametrize("exponent", [65537, (1 << 64) - 1, (1 << 64) + 1, (1 << 256) - 1])
def test_rsa_limit_is_mathematical_and_independent_of_modulus(
    pss: bool, bits: int, exponent: int
) -> None:
    assert MAX_RSA_PUBLIC_EXPONENT_BITS == 64
    certificate = _rsa_certificate(exponent, pss=pss, bits=bits)
    public = certificate.public_key()
    assert isinstance(public, rsa.RSAPublicKey)
    assert public.public_numbers().e == exponent
    if exponent.bit_length() <= 64:
        # UINT64_MAX requires nine DER INTEGER content bytes, including sign padding.
        _check_rsa_public_exponents([certificate])
        validate_certificate_message(_certificate_message([certificate]))
    else:
        with pytest.raises(ProofVerificationError, match=LIMIT_ERROR):
            _check_rsa_public_exponents([certificate])
        with pytest.raises(ProofVerificationError, match=LIMIT_ERROR):
            validate_certificate_message(_certificate_message([certificate]))


@pytest.mark.parametrize("pss", [False, True], ids=["rsae", "pss"])
@pytest.mark.parametrize("position", [0, 1, 7], ids=["leaf", "intermediate", "last-unused"])
def test_every_supplied_certificate_is_checked_before_path_or_cv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pss: bool, position: int
) -> None:
    root, leaf = _ec_identity()
    roots = tmp_path / "roots.pem"
    roots.write_bytes(root.public_bytes(PEM))
    certs = [leaf] + [root] * position
    certs[position] = _rsa_certificate((1 << 64) + 1, pss=pss)
    proof = _proof(certs)
    monkeypatch.setattr(
        "connectcoin_p2c_tools.verify._verify_path", lambda *args: pytest.fail("path reached")
    )
    monkeypatch.setattr(
        "connectcoin_p2c_tools.verify._verify_certificate_signature",
        lambda *args: pytest.fail("CV reached"),
    )
    with pytest.raises(ProofVerificationError, match=LIMIT_ERROR):
        verify_connection_proof(proof, roots, enforce_root_pin=False)


@pytest.mark.parametrize("pss", [False, True], ids=["rsae", "pss"])
def test_unused_boundary_certificate_and_root_remain_acceptable(tmp_path: Path, pss: bool) -> None:
    root, leaf = _ec_identity()
    boundary = _rsa_certificate((1 << 64) - 1, pss=pss)
    roots = tmp_path / "roots.pem"
    roots.write_bytes(root.public_bytes(PEM) + boundary.public_bytes(PEM))
    validate_root_bundle(roots, 1, enforce_root_pin=False)
    verified = verify_connection_proof(_proof([leaf, boundary]), roots, enforce_root_pin=False)
    assert verified.certificate_count == 2


@pytest.mark.parametrize("pss", [False, True], ids=["rsae", "pss"])
def test_unused_root_exponent_is_checked_before_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pss: bool
) -> None:
    root, leaf = _ec_identity()
    invalid_root = _rsa_certificate((1 << 64) + 1, pss=pss)
    roots = tmp_path / "roots.pem"
    roots.write_bytes(root.public_bytes(PEM) + invalid_root.public_bytes(PEM))
    with pytest.raises(ProofVerificationError, match=LIMIT_ERROR):
        validate_root_bundle(roots, 1, enforce_root_pin=False)
    monkeypatch.setattr(
        "connectcoin_p2c_tools.verify._verify_path", lambda *args: pytest.fail("path reached")
    )
    with pytest.raises(ProofVerificationError, match=LIMIT_ERROR):
        verify_connection_proof(_proof([leaf]), roots, enforce_root_pin=False)


@pytest.mark.parametrize("pss", [False, True], ids=["rsae", "pss"])
def test_direct_cv_helper_cannot_skip_the_exponent_guard(pss: bool) -> None:
    _, leaf = _ec_identity()
    proof = _proof([leaf])
    parsed = parse_proof(proof.proof, proof.domain, proof.challenge)
    with pytest.raises(ProofVerificationError, match=LIMIT_ERROR):
        _verify_certificate_signature(_rsa_certificate((1 << 64) + 1, pss=pss), parsed)


@pytest.mark.parametrize("pss", [False, True], ids=["rsae", "pss"])
def test_capture_rejects_certificate_before_waiting_for_cv(
    monkeypatch: pytest.MonkeyPatch, pss: bool
) -> None:
    _, leaf = _ec_identity()
    certificate = _certificate_message([leaf, _rsa_certificate((1 << 64) + 1, pss=pss)])
    server_public = (
        x25519.X25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    hello = b""
    records = 0

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def settimeout(self, timeout: float) -> None:
            pass

        def connect(self, address: object) -> None:
            pass

        def sendall(self, data: bytes) -> None:
            nonlocal hello
            hello = data[5:]

    def recv_record(*args: object) -> tuple[int, bytes, bytes]:
        nonlocal records
        records += 1
        if records == 1:
            session_size = hello[38]
            return (
                CONTENT_HANDSHAKE,
                b"",
                _server_hello(hello[39 : 39 + session_size], server_public),
            )
        if records == 2:
            return CONTENT_APPLICATION_DATA, b"", b"encrypted-record-fixture"
        pytest.fail("capture waited for CertificateVerify after receiving an invalid exponent")

    monkeypatch.setattr("connectcoin_p2c_tools.tls13.socket.socket", lambda *args: Connection())
    monkeypatch.setattr("connectcoin_p2c_tools.tls13._recv_record", recv_record)
    monkeypatch.setattr(
        "connectcoin_p2c_tools.tls13._decrypt_record",
        lambda *args: (CONTENT_HANDSHAKE, _handshake(8, b"\x00\x00") + certificate),
    )
    endpoint = Endpoint(socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 1), "127.0.0.1")
    with pytest.raises(TLSGenerationError, match=LIMIT_ERROR):
        capture_tls13_proof(endpoint, "example.com", b"\x11" * 32, signature_algorithms_mask=1)
    assert records == 2


def test_early_certificate_parser_keeps_protocol_bounds() -> None:
    cert = _rsa_certificate(65537)
    message = _certificate_message([cert])
    assert parse_certificate_message(message) == (cert.public_bytes(DER),)
    with pytest.raises(ProofFormatError, match="trailing bytes"):
        parse_certificate_message(message + b"\x00")
    with pytest.raises(ProofFormatError, match="too many certificates"):
        parse_certificate_message(_certificate_message([cert] * 9))
    with pytest.raises(ProofFormatError, match="size limit"):
        parse_certificate_message(_handshake(11, b"\x00" * (48 * 1024)))
