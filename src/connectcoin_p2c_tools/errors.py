class P2CError(ValueError):
    """A malformed or invalid P2C value."""


class ProofFormatError(P2CError):
    """A binary proof does not use the canonical P2C v1 encoding."""


class ProofVerificationError(P2CError):
    """A structurally valid proof fails a cryptographic or policy check."""
