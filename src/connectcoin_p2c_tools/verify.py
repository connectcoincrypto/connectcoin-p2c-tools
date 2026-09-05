from __future__ import annotations

import hashlib
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .envelope import ConnectionProof
from .errors import ProofVerificationError
from .hashes import internal_hash_to_display, meets_work_target
from .protocol import (
    ECDSA_SECP256R1_SHA256,
    MAX_CERTIFICATES,
    RSA_PSS_PSS_SHA256,
    RSA_PSS_RSAE_SHA256,
    ParsedProof,
    parse_proof,
)

ROOTS_V1_SHA256 = "f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9"
OID_RSA_ENCRYPTION = ObjectIdentifier("1.2.840.113549.1.1.1")
OID_RSASSA_PSS = ObjectIdentifier("1.2.840.113549.1.1.10")
TLS13_SERVER_CERTIFICATE_VERIFY_CONTEXT = b"TLS 1.3, server CertificateVerify"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    challenge: str
    transcript_hash: str
    connection_work_hash: str
    certificate_count: int
    certificate_verify_scheme: int


def _load_certificates(parsed: ParsedProof) -> list[x509.Certificate]:
    certificates: list[x509.Certificate] = []
    for position, encoded in enumerate(parsed.certificate_chain):
        try:
            certificates.append(x509.load_der_x509_certificate(encoded))
        except ValueError as exc:
            raise ProofVerificationError(
                f"certificate {position} is not a valid DER X.509 certificate"
            ) from exc
    return certificates


def _load_roots(path: str | Path, version: int, enforce_root_pin: bool) -> list[x509.Certificate]:
    try:
        encoded = Path(path).read_bytes()
    except OSError as exc:
        raise ProofVerificationError(f"cannot read trusted root bundle: {exc}") from exc
    if version != 1:
        raise ProofVerificationError(f"unsupported root_certificates_version {version}")
    if enforce_root_pin and hashlib.sha256(encoded).hexdigest() != ROOTS_V1_SHA256:
        raise ProofVerificationError(
            "root bundle version 1 does not match its consensus SHA-256 pin"
        )
    try:
        # The immutable Mozilla-derived bundle contains legacy trust anchors
        # that modern WebPKI would not issue today. They remain parseable in
        # the version range pinned by this project and are consensus data.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            roots = x509.load_pem_x509_certificates(encoded)
    except ValueError as exc:
        raise ProofVerificationError("trusted root bundle is not valid PEM") from exc
    if not roots:
        raise ProofVerificationError("trusted root bundle contains no certificates")
    return roots


def validate_root_bundle(
    roots_path: str | Path, root_certificates_version: int, *, enforce_root_pin: bool = True
) -> None:
    """Validate a root bundle before a potentially long proof search."""
    _load_roots(roots_path, root_certificates_version, enforce_root_pin)


def _check_supplied_certificate_times(
    certificates: list[x509.Certificate], validation_time: int
) -> None:
    try:
        moment = datetime.fromtimestamp(validation_time, UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise ProofVerificationError("validation_time cannot be represented") from exc
    for position, certificate in enumerate(certificates):
        if moment < certificate.not_valid_before_utc or moment > certificate.not_valid_after_utc:
            raise ProofVerificationError(
                f"certificate {position} is not valid at the requested block median time"
            )


def _check_leaf_usage(leaf: x509.Certificate) -> None:
    try:
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        pass
    else:
        if not key_usage.digital_signature:
            raise ProofVerificationError("leaf certificate does not permit digital signatures")
    try:
        extended_usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        pass
    else:
        any_usage = ObjectIdentifier("2.5.29.37.0")
        if (
            ExtendedKeyUsageOID.SERVER_AUTH not in extended_usage
            and any_usage not in extended_usage
        ):
            raise ProofVerificationError(
                "leaf certificate is not valid for TLS server authentication"
            )


def _verify_path(
    certificates: list[x509.Certificate],
    roots: list[x509.Certificate],
    domain: str,
    validation_time: int,
) -> None:
    try:
        moment = datetime.fromtimestamp(validation_time, UTC)
        verifier = (
            PolicyBuilder()
            .store(Store(roots))
            .time(moment)
            .max_chain_depth(MAX_CERTIFICATES - 1)
            .build_server_verifier(x509.DNSName(domain))
        )
        verifier.verify(certificates[0], certificates[1:])
    except (OSError, OverflowError, ValueError, VerificationError) as exc:
        raise ProofVerificationError(
            f"certificate path or domain validation failed: {exc}"
        ) from exc


def _certificate_verify_message(transcript_hash: bytes) -> bytes:
    return b"\x20" * 64 + TLS13_SERVER_CERTIFICATE_VERIFY_CONTEXT + b"\x00" + transcript_hash


def _verify_certificate_signature(leaf: x509.Certificate, parsed: ParsedProof) -> None:
    public_key = leaf.public_key()
    message = _certificate_verify_message(parsed.transcript_hash)
    scheme = parsed.certificate_verify_scheme
    try:
        if scheme == ECDSA_SECP256R1_SHA256:
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
                public_key.curve, ec.SECP256R1
            ):
                raise ProofVerificationError(
                    "CertificateVerify ECDSA scheme does not match a P-256 leaf key"
                )
            public_key.verify(
                parsed.certificate_verify_signature, message, ec.ECDSA(hashes.SHA256())
            )
        elif scheme in {RSA_PSS_RSAE_SHA256, RSA_PSS_PSS_SHA256}:
            if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
                raise ProofVerificationError(
                    "CertificateVerify RSA-PSS scheme requires an RSA key of at least 2048 bits"
                )
            expected_oid = OID_RSA_ENCRYPTION if scheme == RSA_PSS_RSAE_SHA256 else OID_RSASSA_PSS
            if leaf.public_key_algorithm_oid != expected_oid:
                raise ProofVerificationError(
                    "CertificateVerify RSA-PSS scheme does not match the leaf key encoding"
                )
            public_key.verify(
                parsed.certificate_verify_signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        else:  # Protected by the structural parser.
            raise ProofVerificationError("unsupported CertificateVerify signature scheme")
    except InvalidSignature as exc:
        raise ProofVerificationError("invalid TLS 1.3 CertificateVerify signature") from exc


def verify_connection_proof(
    envelope: ConnectionProof,
    roots_path: str | Path,
    *,
    enforce_root_pin: bool = True,
) -> VerificationResult:
    parsed = parse_proof(envelope.proof, envelope.domain, envelope.challenge)
    if not meets_work_target(parsed.connection_work_hash, envelope.connection_work_target):
        raise ProofVerificationError("connection work hash exceeds the output target")
    certificates = _load_certificates(parsed)
    roots = _load_roots(roots_path, envelope.root_certificates_version, enforce_root_pin)
    _check_supplied_certificate_times(certificates, envelope.validation_time)
    _check_leaf_usage(certificates[0])
    _verify_path(certificates, roots, envelope.domain, envelope.validation_time)
    _verify_certificate_signature(certificates[0], parsed)
    return VerificationResult(
        challenge=envelope.challenge.hex(),
        transcript_hash=parsed.transcript_hash.hex(),
        connection_work_hash=internal_hash_to_display(parsed.connection_work_hash),
        certificate_count=len(parsed.certificate_chain),
        certificate_verify_scheme=parsed.certificate_verify_scheme,
    )
