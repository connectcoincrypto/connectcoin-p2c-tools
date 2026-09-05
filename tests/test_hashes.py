from __future__ import annotations

import json
from pathlib import Path

import pytest

from connectcoin_p2c_tools.hashes import claim_challenge


def test_challenge_matches_connectcoin_core_vector() -> None:
    vector = json.loads(
        (Path(__file__).parents[1] / "vectors" / "challenge-v1.json").read_text(encoding="utf-8")
    )
    result = claim_challenge(vector["txid"], vector["input_index"])
    assert result.hex() == vector["clienthello_random"]


@pytest.mark.parametrize("input_index", [-1, 2**32])
def test_challenge_rejects_out_of_range_input_index(input_index: int) -> None:
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        claim_challenge("00" * 32, input_index)


def test_challenge_commits_input_index() -> None:
    txid = "01" * 32
    assert claim_challenge(txid, 0) != claim_challenge(txid, 1)
