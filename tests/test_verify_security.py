"""Offline full-proof regressions for the pinned X.509 provider's security fixes."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from connectcoin_p2c_tools.errors import ProofVerificationError
from connectcoin_p2c_tools.protocol import MAX_CERTIFICATES, parse_proof
from connectcoin_p2c_tools.verify import verify_connection_proof

from .helpers import make_proof_from_chain


def _certificate(
    subject: str,
    issuer: str,
    key: ec.EllipticCurvePrivateKey,
    issuer_key: ec.EllipticCurvePrivateKey,
    serial: int,
    *,
    ca: bool,
    dns: str | None = None,
    permitted_dns: str | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, None, None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False
        )
    )
    if dns is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), False)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
        )
    if permitted_dns is not None:
        builder = builder.add_extension(
            x509.NameConstraints([x509.DNSName(permitted_dns)], None), True
        )
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.mark.parametrize(
    ("leaf_dns", "domain", "accepted"),
    [
        ("foo.example.com", "foo.example.com", True),
        ("*.foo.example.com", "bar.foo.example.com", True),
        ("bar.example.com", "bar.example.com", False),
        ("*.example.com", "bar.example.com", False),
        ("*.example.com", "foo.example.com", False),
    ],
)
def test_constrained_ca_cannot_expand_its_dns_scope(
    tmp_path: Path, leaf_dns: str, domain: str, accepted: bool
) -> None:
    """GHSA-m2h6-j472-rp4c: a wildcard's whole scope must fit the delegation."""
    # Deterministic keys are public test material, never used outside these fixtures.
    root_key = ec.derive_private_key(101, ec.SECP256R1())
    ca_key = ec.derive_private_key(102, ec.SECP256R1())
    leaf_key = ec.derive_private_key(103, ec.SECP256R1())
    root = _certificate("Root", "Root", root_key, root_key, 1, ca=True)
    intermediate = _certificate(
        "Constrained CA", "Root", ca_key, root_key, 2, ca=True, permitted_dns="foo.example.com"
    )
    leaf = _certificate("Leaf", "Constrained CA", leaf_key, ca_key, 3, ca=False, dns=leaf_dns)
    fixture = make_proof_from_chain(
        domain=domain, leaf_key=leaf_key, certificates=[leaf, intermediate], roots=[root]
    )
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    if accepted:
        result = verify_connection_proof(fixture.envelope, roots, enforce_root_pin=False)
        assert result.certificate_count == 2
    else:
        with pytest.raises(ProofVerificationError, match="certificate path or domain validation"):
            verify_connection_proof(fixture.envelope, roots, enforce_root_pin=False)


_VERIFY_SUBPROCESS = """
import json
import sys
from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.errors import ProofVerificationError
from connectcoin_p2c_tools.verify import verify_connection_proof

envelope = ConnectionProof.from_dict(json.load(sys.stdin))
try:
    result = verify_connection_proof(envelope, sys.argv[1], enforce_root_pin=False)
except ProofVerificationError as exc:
    print("rejected: " + str(exc))
else:
    print("accepted: " + str(result.certificate_count))
"""


@pytest.mark.parametrize("trusted_issuer", [False, True])
def test_duplicate_self_signed_candidates_have_bounded_verification(
    tmp_path: Path, trusted_issuer: bool
) -> None:
    """GHSA-jwv3-5hgf-82ww: bound cyclic path search at the real protocol limit."""
    ca_key = ec.derive_private_key(201, ec.SECP256R1())
    unrelated_key = ec.derive_private_key(202, ec.SECP256R1())
    leaf_key = ec.derive_private_key(203, ec.SECP256R1())
    looping_ca = _certificate("Looping CA", "Looping CA", ca_key, ca_key, 4, ca=True)
    unrelated_root = _certificate(
        "Unrelated root", "Unrelated root", unrelated_key, unrelated_key, 5, ca=True
    )
    leaf = _certificate("Leaf", "Looping CA", leaf_key, ca_key, 6, ca=False, dns="example.com")
    fixture = make_proof_from_chain(
        domain="example.com",
        leaf_key=leaf_key,
        certificates=[leaf] + [looping_ca] * (MAX_CERTIFICATES - 1),
        roots=[looping_ca if trusted_issuer else unrelated_root],
    )
    parsed = parse_proof(
        fixture.envelope.proof, fixture.envelope.domain, fixture.envelope.challenge
    )
    assert len(parsed.certificate_chain) == MAX_CERTIFICATES
    assert len(set(parsed.certificate_chain[1:])) == 1
    roots = tmp_path / "roots.pem"
    roots.write_bytes(fixture.roots_pem)
    # A killable child bounds this regression even if the old provider is restored.
    # No timing threshold is imposed on the in-process test runner or public server.
    completed = subprocess.run(
        [sys.executable, "-c", _VERIFY_SUBPROCESS, str(roots)],
        input=json.dumps(fixture.envelope.to_dict()),
        text=True,
        capture_output=True,
        timeout=5,
        check=True,
    )
    if trusted_issuer:
        assert completed.stdout.strip() == f"accepted: {MAX_CERTIFICATES}"
    else:
        assert completed.stdout.startswith("rejected: certificate path or domain validation")
