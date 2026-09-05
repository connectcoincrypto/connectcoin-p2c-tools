from __future__ import annotations

import pytest

from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.errors import ProofFormatError

from .helpers import make_valid_proof


def test_envelope_round_trip() -> None:
    original = make_valid_proof().envelope
    assert ConnectionProof.from_dict(original.to_dict()) == original


def test_envelope_rejects_unknown_fields() -> None:
    value = make_valid_proof().envelope.to_dict()
    value["mode"] = "domain"
    with pytest.raises(ProofFormatError, match="unknown fields"):
        ConnectionProof.from_dict(value)


def test_envelope_rejects_noncanonical_domain() -> None:
    value = make_valid_proof().envelope.to_dict()
    value["domain"] = "Example.COM"
    with pytest.raises(ProofFormatError, match="not canonical"):
        ConnectionProof.from_dict(value)
