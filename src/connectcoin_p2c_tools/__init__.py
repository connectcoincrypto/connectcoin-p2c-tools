"""Independent ConnectCoin pay-to-connect proof tools."""

from .envelope import ConnectionProof
from .generator import GenerationOptions, GenerationResult, generate_connection_proof
from .hashes import claim_challenge, tagged_hash
from .protocol import ParsedProof, parse_proof
from .verify import VerificationResult, verify_connection_proof

__all__ = [
    "ConnectionProof",
    "GenerationOptions",
    "GenerationResult",
    "ParsedProof",
    "VerificationResult",
    "claim_challenge",
    "generate_connection_proof",
    "parse_proof",
    "tagged_hash",
    "verify_connection_proof",
]
