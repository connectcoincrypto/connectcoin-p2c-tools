from __future__ import annotations

import pytest

from connectcoin_p2c_tools.errors import ProofFormatError
from connectcoin_p2c_tools.signatures import (
    accepted_signature_algorithms,
    signature_scheme_allowed,
    validate_signature_algorithms_mask,
)


@pytest.mark.parametrize(
    "mask, expected",
    [
        (1, (0x0403,)),
        (2, (0x0804,)),
        (3, (0x0403, 0x0804)),
        (4, (0x0809,)),
        (5, (0x0403, 0x0809)),
        (6, (0x0804, 0x0809)),
        (7, (0x0403, 0x0804, 0x0809)),
    ],
)
def test_all_output_masks(mask: int, expected: tuple[int, ...]) -> None:
    assert validate_signature_algorithms_mask(mask) == mask
    algorithms = accepted_signature_algorithms(mask)
    assert tuple(algorithm.scheme for algorithm in algorithms) == expected
    assert sum(algorithm.mask for algorithm in algorithms) == mask
    for scheme in (0x0403, 0x0804, 0x0809, 0x0805, 0x0401):
        assert signature_scheme_allowed(mask, scheme) == (scheme in expected)


def test_standard_algorithm_names() -> None:
    assert [algorithm.name for algorithm in accepted_signature_algorithms(7)] == [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pss_pss_sha256",
    ]


@pytest.mark.parametrize("invalid", [None, False, True, 0, -1, 8, 255, 1.0, 2.5, "7", []])
def test_invalid_mask_never_defaults_to_all(invalid: object) -> None:
    with pytest.raises(ProofFormatError, match="signature_algorithms_mask"):
        validate_signature_algorithms_mask(invalid)
