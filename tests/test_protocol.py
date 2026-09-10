from __future__ import annotations

import json
import random
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from connectcoin_p2c_tools.errors import ProofFormatError
from connectcoin_p2c_tools.protocol import PROOF_VERSION, ParsedProof, parse_proof

from .helpers import _handshake, make_valid_proof


@pytest.fixture
def work_vector() -> dict[str, Any]:
    return json.loads(
        (Path(__file__).parents[1] / "vectors" / "work-v2.json").read_text(encoding="utf-8")
    )


def _parse_vector(work_vector: dict[str, Any], encoded: bytes | None = None) -> ParsedProof:
    return parse_proof(
        bytes.fromhex(work_vector["proof"]) if encoded is None else encoded,
        work_vector["domain"],
        bytes.fromhex(work_vector["clienthello_random"]),
    )


def test_structural_parser_accepts_valid_proof() -> None:
    envelope = make_valid_proof().envelope
    assert PROOF_VERSION == 2
    assert envelope.proof[0] == 2
    parsed = parse_proof(envelope.proof, envelope.domain, envelope.challenge)
    assert len(parsed.certificate_chain) == 1
    assert parsed.certificate_verify_scheme == 0x0403
    assert len(parsed.transcript_hash) == 32
    assert len(parsed.connection_work_hash) == 32


def test_parser_matches_independent_work_v2_vector(work_vector: dict[str, Any]) -> None:
    parsed = _parse_vector(work_vector)
    assert parsed.transcript_hash.hex() == work_vector["transcript_hash"]
    assert parsed.connection_work_hash.hex() == work_vector["connection_work_hash_raw"]
    assert parsed.certificate_verify == bytes.fromhex(work_vector["certificate_verify"])
    assert b"\x02" + b"".join(parsed.messages) == bytes.fromhex(work_vector["proof"])


@pytest.mark.parametrize("version", [0, 1, 3, 255])
def test_parser_accepts_only_proof_v2(work_vector: dict[str, Any], version: int) -> None:
    encoded = bytes.fromhex(work_vector["proof"])
    with pytest.raises(ProofFormatError, match="unsupported P2C proof version"):
        _parse_vector(work_vector, bytes([version]) + encoded[1:])


@pytest.mark.parametrize("scheme", [0x0403, 0x0804, 0x0809])
@pytest.mark.parametrize(
    "signature", [b"\x00", b"different signature", b"\xff" * 256], ids=["one", "changed", "long"]
)
def test_work_excludes_entire_certificate_verify(
    work_vector: dict[str, Any], scheme: int, signature: bytes
) -> None:
    original = _parse_vector(work_vector)
    certificate_verify = _handshake(
        15, scheme.to_bytes(2, "big") + len(signature).to_bytes(2, "big") + signature
    )
    encoded = b"\x02" + b"".join(original.messages[:4]) + certificate_verify
    changed = _parse_vector(work_vector, encoded)
    assert changed.certificate_verify_scheme == scheme
    assert changed.certificate_verify_signature == signature
    assert changed.certificate_verify != original.certificate_verify
    assert changed.connection_work_hash == original.connection_work_hash
    assert changed.transcript_hash == original.transcript_hash


@pytest.mark.parametrize(
    "certificate_verify",
    [
        b"",  # Although excluded from work, CertificateVerify is still mandatory.
        _handshake(15, b"\x04\x03\x00\x00"),
        _handshake(15, b"\x04\x03\x00\x02\x01"),
        _handshake(15, b"\x04\x03\x00\x01\x01\x02"),
        _handshake(15, b"\x08\x07\x00\x01\x01"),  # Unsupported Ed25519.
        _handshake(16, b"\x04\x03\x00\x01\x01"),
        _handshake(15, b"\x04\x03" + (8185).to_bytes(2, "big") + b"\x01" * 8185),
    ],
    ids=["missing", "empty", "truncated", "trailing", "unsupported", "wrong-type", "too-large"],
)
def test_excluded_certificate_verify_must_still_be_structurally_valid(
    work_vector: dict[str, Any], certificate_verify: bytes
) -> None:
    parsed = _parse_vector(work_vector)
    with pytest.raises(ProofFormatError):
        _parse_vector(work_vector, b"\x02" + b"".join(parsed.messages[:4]) + certificate_verify)


def test_certificate_verify_must_select_an_offered_scheme() -> None:
    envelope = make_valid_proof().envelope  # ClientHello offers only ECDSA.
    parsed = parse_proof(envelope.proof, envelope.domain, envelope.challenge)
    verify = _handshake(15, b"\x08\x04\x00\x01\x01")
    with pytest.raises(ProofFormatError, match="unoffered signature scheme"):
        parse_proof(
            b"\x02" + b"".join(parsed.messages[:4]) + verify, envelope.domain, envelope.challenge
        )


@pytest.mark.parametrize("message_index", range(4))
def test_parser_work_commits_each_authenticated_message(
    work_vector: dict[str, Any], message_index: int
) -> None:
    parsed = _parse_vector(work_vector)
    messages = list(parsed.messages)
    original = messages[message_index]
    if message_index == 0:  # Change a structurally valid ClientHello key share byte.
        messages[0] = original[:-1] + bytes([original[-1] ^ 1])
    elif message_index == 1:  # Change ServerHello.random.
        messages[1] = original[:6] + bytes([original[6] ^ 1]) + original[7:]
    elif message_index == 2:  # Add an allowed opaque extension and update its header.
        messages[2] = _handshake(8, b"\x00\x05\xff\xff\x00\x01\x01")
    else:  # Alter certificate bytes; the structural parser does not validate DER.
        messages[3] = original[:11] + bytes([original[11] ^ 1]) + original[12:]
    changed = _parse_vector(work_vector, b"\x02" + b"".join(messages))
    assert changed.connection_work_hash != parsed.connection_work_hash
    assert changed.transcript_hash != parsed.transcript_hash


def test_every_truncated_proof_prefix_is_rejected(work_vector: dict[str, Any]) -> None:
    encoded = bytes.fromhex(work_vector["proof"])
    for length in range(len(encoded)):
        with pytest.raises(ProofFormatError):
            _parse_vector(work_vector, encoded[:length])


def test_structural_parser_rejects_wrong_challenge() -> None:
    envelope = make_valid_proof().envelope
    with pytest.raises(ProofFormatError, match="claim challenge"):
        parse_proof(envelope.proof, envelope.domain, b"\x00" * 32)


def test_structural_parser_rejects_wrong_domain() -> None:
    envelope = make_valid_proof().envelope
    with pytest.raises(ProofFormatError, match="server_name"):
        parse_proof(envelope.proof, "other.example", envelope.challenge)


def test_structural_parser_rejects_trailing_data() -> None:
    envelope = make_valid_proof().envelope
    with pytest.raises(ProofFormatError, match="trailing bytes"):
        parse_proof(envelope.proof + b"\x00", envelope.domain, envelope.challenge)


def test_malformed_inputs_fail_without_parser_crashes() -> None:
    random_source = random.Random(0xC0_22_EC_7)
    challenge = b"\x00" * 32
    for _ in range(2_000):
        encoded = random_source.randbytes(random_source.randrange(0, 1024))
        with suppress(ProofFormatError):
            parse_proof(encoded, "example.com", challenge)
