from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from connectcoin_p2c_tools.hashes import (
    CLAIM_TAG,
    WORK_TAG,
    claim_challenge,
    connection_work_hash,
    internal_hash_to_display,
    meets_work_target,
)


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


def test_work_v2_matches_independently_calculated_vector() -> None:
    vector = json.loads(
        (Path(__file__).parents[1] / "vectors" / "work-v2.json").read_text(encoding="utf-8")
    )
    client, server, extensions, certificate = (bytes.fromhex(v) for v in vector["messages"])
    messages = (client, server, extensions, certificate)
    result = connection_work_hash(messages)
    assert result.hex() == vector["connection_work_hash_raw"]
    assert internal_hash_to_display(result) == vector["connection_work_hash_display"]
    transcript = b"".join(messages)
    assert hashlib.sha256(transcript).hexdigest() == vector["transcript_hash"]
    tag = hashlib.sha256(b"ConnectCoin/P2C/work/v2").digest()
    assert result == hashlib.sha256(tag + tag + transcript).digest()
    # Do not hash only bodies, a version prefix, or any CertificateVerify byte.
    assert result != hashlib.sha256(tag + tag + b"".join(m[4:] for m in messages)).digest()
    assert result != hashlib.sha256(tag + tag + b"\x02" + transcript).digest()
    verify = bytes.fromhex(vector["certificate_verify"])
    assert result != hashlib.sha256(tag + tag + transcript + verify).digest()


def test_work_and_claim_have_independent_versioned_tags() -> None:
    assert CLAIM_TAG == b"ConnectCoin/P2C/claim/v1"
    assert WORK_TAG == b"ConnectCoin/P2C/work/v2"
    messages = (b"client", b"server", b"extensions", b"certificate")
    work = connection_work_hash(messages)
    old_tag = hashlib.sha256(b"ConnectCoin/P2C/work/v1").digest()
    assert work != hashlib.sha256(old_tag + old_tag + b"".join(messages)).digest()


@pytest.mark.parametrize("index", range(4))
def test_work_commits_every_full_transcript_message(index: int) -> None:
    messages = (b"client", b"server", b"extensions", b"certificate")
    changed = list(messages)
    changed[index] += b"\x00"
    assert connection_work_hash(messages) != connection_work_hash(tuple(changed))


def test_work_rejects_old_five_message_api() -> None:
    with pytest.raises(ValueError, match="exactly four messages"):
        connection_work_hash((b"client", b"server", b"extensions", b"certificate", b"verify"))


def test_work_target_uses_little_endian_integer_and_includes_equality() -> None:
    work_hash = b"\x01" + b"\x00" * 31
    assert meets_work_target(work_hash, "00" * 31 + "01")
    assert meets_work_target(work_hash, "00" * 31 + "02")
    assert not meets_work_target(work_hash, "00" * 32)
    assert not meets_work_target(b"\x00" * 31 + b"\x01", "00" * 31 + "ff")
