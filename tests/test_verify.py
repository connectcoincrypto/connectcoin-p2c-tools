from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from connectcoin_p2c_tools.errors import ProofVerificationError
from connectcoin_p2c_tools.verify import verify_connection_proof

from .helpers import make_valid_proof


def test_full_independent_verification(tmp_path: Path) -> None:
    fixture = make_valid_proof()
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    result = verify_connection_proof(fixture.envelope, roots, enforce_root_pin=False)
    assert result.challenge == fixture.envelope.challenge.hex()
    assert result.certificate_count == 1
    assert result.certificate_verify_scheme == 0x0403


def test_full_verification_rejects_signature_mutation(tmp_path: Path) -> None:
    fixture = make_valid_proof()
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    damaged = bytearray(fixture.envelope.proof)
    damaged[-1] ^= 1
    envelope = replace(fixture.envelope, proof=bytes(damaged))
    with pytest.raises(ProofVerificationError, match="CertificateVerify signature"):
        verify_connection_proof(envelope, roots, enforce_root_pin=False)


def test_full_verification_rejects_expired_leaf(tmp_path: Path) -> None:
    fixture = make_valid_proof()
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    envelope = replace(fixture.envelope, validation_time=2_100_000_000)
    with pytest.raises(ProofVerificationError, match="not valid"):
        verify_connection_proof(envelope, roots, enforce_root_pin=False)


def test_root_bundle_pin_is_enforced(tmp_path: Path) -> None:
    fixture = make_valid_proof()
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    with pytest.raises(ProofVerificationError, match="consensus SHA-256 pin"):
        verify_connection_proof(fixture.envelope, roots)
