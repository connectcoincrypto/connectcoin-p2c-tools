from __future__ import annotations

import random
from contextlib import suppress

import pytest

from connectcoin_p2c_tools.errors import ProofFormatError
from connectcoin_p2c_tools.protocol import parse_proof

from .helpers import make_valid_proof


def test_structural_parser_accepts_valid_proof() -> None:
    envelope = make_valid_proof().envelope
    parsed = parse_proof(envelope.proof, envelope.domain, envelope.challenge)
    assert len(parsed.certificate_chain) == 1
    assert parsed.certificate_verify_scheme == 0x0403
    assert len(parsed.transcript_hash) == 32
    assert len(parsed.connection_work_hash) == 32


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
