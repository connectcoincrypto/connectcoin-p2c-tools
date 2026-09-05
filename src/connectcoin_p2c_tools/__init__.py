"""Independent ConnectCoin pay-to-connect proof tools."""

from .envelope import ConnectionProof
from .hashes import claim_challenge, tagged_hash
from .protocol import ParsedProof, parse_proof
from .verify import VerificationResult, verify_connection_proof

__all__ = [
    "ConnectionProof",
    "ParsedProof",
    "VerificationResult",
    "claim_challenge",
    "parse_proof",
    "tagged_hash",
    "verify_connection_proof",
]
