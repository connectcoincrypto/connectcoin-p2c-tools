from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from connectcoin_p2c_tools.errors import ProofVerificationError
from connectcoin_p2c_tools.protocol import parse_proof
from connectcoin_p2c_tools.verify import _verify_certificate_signature, verify_connection_proof

from .helpers import make_valid_proof
from .helpers_rsa_verify import SHA384_OID, der, make_rsa_proof, pss_parameters


def test_full_independent_verification(tmp_path: Path) -> None:
    fixture = make_valid_proof()
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    result = verify_connection_proof(fixture.envelope, roots, enforce_root_pin=False)
    assert result.challenge == fixture.envelope.challenge.hex()
    assert result.certificate_count == 1
    assert result.certificate_verify_scheme == 0x0403
    assert result.signature_algorithms_mask == fixture.envelope.signature_algorithms_mask


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


@pytest.mark.parametrize("mask", [1, 3, 5, 7])
def test_ecdsa_is_verified_for_every_allowing_output_mask(tmp_path: Path, mask: int) -> None:
    fixture = make_valid_proof()
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    envelope = replace(fixture.envelope, signature_algorithms_mask=mask)
    result = verify_connection_proof(envelope, roots, enforce_root_pin=False)
    assert result.signature_algorithms_mask == mask


@pytest.mark.parametrize("mask", [2, 4, 6])
def test_disallowed_scheme_is_rejected_before_crypto_or_root_io(tmp_path: Path, mask: int) -> None:
    fixture = make_valid_proof()
    damaged = bytearray(fixture.envelope.proof)
    damaged[-1] ^= 1
    envelope = replace(fixture.envelope, proof=bytes(damaged), signature_algorithms_mask=mask)
    with pytest.raises(ProofVerificationError, match="not allowed by the output"):
        verify_connection_proof(envelope, tmp_path / "missing-roots.pem")


@pytest.mark.parametrize(
    ("scheme", "mask", "pss_spki", "parameters"),
    [
        (0x0804, 2, False, b""),
        (0x0804, 6, False, b""),
        (0x0809, 4, True, b""),
        (0x0809, 6, True, pss_parameters()),
        (0x0809, 7, True, pss_parameters(minimum_salt=20)),
        (0x0809, 4, True, pss_parameters(minimum_salt=None)),
        (0x0809, 4, True, pss_parameters(minimum_salt=0, trailer=1)),
        (0x0809, 4, True, pss_parameters(null_hash_parameters=False)),
    ],
)
def test_full_rsa_verification(
    tmp_path: Path, scheme: int, mask: int, pss_spki: bool, parameters: bytes
) -> None:
    fixture = make_rsa_proof(scheme=scheme, mask=mask, pss_spki=pss_spki, parameters=parameters)
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    result = verify_connection_proof(fixture.envelope, roots, enforce_root_pin=False)
    assert result.certificate_verify_scheme == scheme
    assert result.signature_algorithms_mask == mask


@pytest.mark.parametrize(("scheme", "pss_spki"), [(0x0809, False), (0x0804, True)])
def test_rsae_and_pss_key_encodings_are_not_interchangeable(scheme: int, pss_spki: bool) -> None:
    fixture = make_rsa_proof(scheme=scheme, pss_spki=pss_spki)
    parsed = parse_proof(
        fixture.envelope.proof, fixture.envelope.domain, fixture.envelope.challenge
    )
    leaf = x509.load_der_x509_certificate(parsed.certificate_chain[0])
    with pytest.raises(ProofVerificationError, match="leaf key encoding"):
        _verify_certificate_signature(leaf, parsed)


@pytest.mark.parametrize(
    "parameters",
    [
        b"\x30\x00",  # Present empty parameters mean SHA-1, NOT unrestricted PSS.
        pss_parameters(hash_oid=SHA384_OID),
        pss_parameters(mgf_hash_oid=SHA384_OID),
        pss_parameters(minimum_salt=33),
        pss_parameters(trailer=2),
    ],
)
def test_pss_spki_restrictions_are_not_lost_by_generic_rsa(parameters: bytes) -> None:
    fixture = make_rsa_proof(scheme=0x0809, pss_spki=True, parameters=parameters)
    parsed = parse_proof(
        fixture.envelope.proof, fixture.envelope.domain, fixture.envelope.challenge
    )
    leaf = x509.load_der_x509_certificate(parsed.certificate_chain[0])
    with pytest.raises(ProofVerificationError, match="RSA-PSS key restrictions"):
        _verify_certificate_signature(leaf, parsed)


@pytest.mark.parametrize(
    "parameters",
    [
        b"\x05\x00",  # NULL is not a valid PSS parameters encoding.
        pss_parameters(minimum_salt=-1),
        der(0x30, der(0xA2, b"\x02\x01\x20") * 2),  # Duplicate parameter.
        der(0x30, der(0xA3, b"\x02\x01\x01") + der(0xA2, b"\x02\x01\x20")),
        der(0x30, der(0xA4, b"\x02\x01\x01")),  # Unknown parameter.
    ],
)
def test_malformed_pss_spki_is_rejected_as_a_proof_error(tmp_path: Path, parameters: bytes) -> None:
    fixture = make_rsa_proof(scheme=0x0809, pss_spki=True, parameters=parameters)
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    with pytest.raises(ProofVerificationError, match=r"valid DER X\.509|RSA-PSS key restrictions"):
        verify_connection_proof(fixture.envelope, roots, enforce_root_pin=False)


@pytest.mark.parametrize(("scheme", "mask", "pss_spki"), [(0x0804, 4, False), (0x0809, 2, True)])
def test_rsa_scheme_must_match_output_mask_before_crypto(
    tmp_path: Path, scheme: int, mask: int, pss_spki: bool
) -> None:
    fixture = make_rsa_proof(scheme=scheme, mask=mask, pss_spki=pss_spki)
    with pytest.raises(ProofVerificationError, match="not allowed by the output"):
        verify_connection_proof(fixture.envelope, tmp_path / "missing-roots.pem")


@pytest.mark.parametrize(("scheme", "pss_spki"), [(0x0804, False), (0x0809, True)])
def test_rsa_certificate_verify_requires_at_least_2048_bits(scheme: int, pss_spki: bool) -> None:
    fixture = make_rsa_proof(scheme=scheme, pss_spki=pss_spki, key_size=1024)
    parsed = parse_proof(
        fixture.envelope.proof, fixture.envelope.domain, fixture.envelope.challenge
    )
    leaf = x509.load_der_x509_certificate(parsed.certificate_chain[0])
    with pytest.raises(ProofVerificationError, match="at least 2048 bits"):
        _verify_certificate_signature(leaf, parsed)


@pytest.mark.parametrize("salt", [0, 20, 31, 33])
def test_rsa_certificate_verify_requires_exactly_32_salt_bytes(salt: int) -> None:
    fixture = make_rsa_proof(signature_salt=salt)
    parsed = parse_proof(
        fixture.envelope.proof, fixture.envelope.domain, fixture.envelope.challenge
    )
    leaf = x509.load_der_x509_certificate(parsed.certificate_chain[0])
    with pytest.raises(ProofVerificationError, match="CertificateVerify signature"):
        _verify_certificate_signature(leaf, parsed)


def test_rsa_certificate_verify_requires_mgf1_sha256() -> None:
    fixture = make_rsa_proof(signature_mgf=hashes.SHA384())
    parsed = parse_proof(
        fixture.envelope.proof, fixture.envelope.domain, fixture.envelope.challenge
    )
    leaf = x509.load_der_x509_certificate(parsed.certificate_chain[0])
    with pytest.raises(ProofVerificationError, match="CertificateVerify signature"):
        _verify_certificate_signature(leaf, parsed)


@pytest.mark.parametrize("curve", [ec.SECP384R1(), ec.SECP521R1()])
def test_ecdsa_certificate_verify_requires_p256(curve: ec.EllipticCurve) -> None:
    fixture = make_valid_proof()
    parsed = parse_proof(
        fixture.envelope.proof, fixture.envelope.domain, fixture.envelope.challenge
    )
    original_leaf = x509.load_der_x509_certificate(parsed.certificate_chain[0])
    key = ec.generate_private_key(curve)
    wrong_curve_leaf = (
        x509.CertificateBuilder()
        .subject_name(original_leaf.subject)
        .issuer_name(original_leaf.issuer)
        .public_key(key.public_key())
        .serial_number(12)
        .not_valid_before(original_leaf.not_valid_before_utc)
        .not_valid_after(original_leaf.not_valid_after_utc)
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(ProofVerificationError, match="P-256 leaf key"):
        _verify_certificate_signature(wrong_curve_leaf, parsed)
