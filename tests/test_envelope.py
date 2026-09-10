from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

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


@pytest.mark.parametrize("mask", range(1, 8))
def test_envelope_round_trips_each_explicit_mask(mask: int, tmp_path: Path) -> None:
    original = replace(make_valid_proof().envelope, signature_algorithms_mask=mask)
    output = tmp_path / "proof.json"
    original.write(output)
    assert ConnectionProof.read(output) == original
    assert original.to_dict()["version"] == 2
    assert original.to_dict()["signature_algorithms_mask"] == mask


def test_envelope_requires_mask() -> None:
    value = make_valid_proof().envelope.to_dict()
    del value["signature_algorithms_mask"]
    with pytest.raises(ProofFormatError, match="missing: signature_algorithms_mask"):
        ConnectionProof.from_dict(value)


@pytest.mark.parametrize("mask", [None, False, True, 0, -1, 8, 255, 1.0, 1.5, "7"])
def test_envelope_rejects_invalid_mask(mask: object) -> None:
    value = make_valid_proof().envelope.to_dict()
    value["signature_algorithms_mask"] = mask
    with pytest.raises(ProofFormatError, match="signature_algorithms_mask"):
        ConnectionProof.from_dict(value)


@pytest.mark.parametrize("version", [1, 0, 3, None, False, True, 2.0, "2"])
def test_envelope_rejects_other_versions(version: object) -> None:
    value = make_valid_proof().envelope.to_dict()
    value["version"] = version
    with pytest.raises(ProofFormatError, match=r"only.*version 2"):
        ConnectionProof.from_dict(value)


def test_envelope_v2_cannot_wrap_a_v1_witness() -> None:
    original = make_valid_proof().envelope
    value = original.to_dict()
    value["proof"] = "01" + original.proof[1:].hex()
    with pytest.raises(ProofFormatError, match="P2C proof version 2"):
        ConnectionProof.from_dict(value)
    with pytest.raises(ProofFormatError, match="P2C proof version 2"):
        replace(original, proof=b"\x01" + original.proof[1:]).to_dict()


def test_generation_context_cannot_be_serialized(tmp_path: Path) -> None:
    context = replace(make_valid_proof().envelope, proof=b"")
    with pytest.raises(ProofFormatError, match="serialized proof"):
        context.write(tmp_path / "empty.json")
    assert not (tmp_path / "empty.json").exists()


def test_direct_constructor_cannot_bypass_mask_validation() -> None:
    with pytest.raises(ProofFormatError, match="signature_algorithms_mask"):
        replace(make_valid_proof().envelope, signature_algorithms_mask=0)


def test_schema_documents_v2_and_required_mask() -> None:
    path = Path(__file__).parents[1] / "schemas" / "connection-proof-v2.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert "signature_algorithms_mask" in schema["required"]
    assert schema["properties"]["signature_algorithms_mask"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 7,
    }
    assert schema["properties"]["version"]["const"] == 2
    pattern = schema["properties"]["proof"]["pattern"]
    assert re.fullmatch(pattern, make_valid_proof().envelope.proof.hex())
    for invalid in ("01", "020", "02aa0", "02AA", "", "00"):
        assert not re.fullmatch(pattern, invalid)
