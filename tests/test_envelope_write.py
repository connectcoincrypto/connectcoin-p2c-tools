from __future__ import annotations

import json
import os
import stat
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.errors import ProofFormatError

from .helpers import make_valid_proof


@pytest.fixture
def proof() -> ConnectionProof:
    return make_valid_proof().envelope


def _make_link(link: Path, target: Path, kind: str) -> None:
    try:
        if kind == "symlink":
            link.symlink_to(target)
        else:
            link.hardlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"{kind} creation is unavailable: {exc}")


@pytest.mark.parametrize("kind", ["file", "hardlink", "symlink"])
@pytest.mark.parametrize("overwrite", [False, True])
def test_write_leaves_predictable_temporary_path_untouched(
    proof: ConnectionProof, tmp_path: Path, kind: str, overwrite: bool
) -> None:
    destination = tmp_path / "proof.json"
    predictable = tmp_path / "proof.json.tmp"
    victim = tmp_path / "unrelated.txt"
    victim.write_bytes(b"unrelated data must survive\n")
    if kind == "file":
        predictable.write_bytes(b"preexisting temporary file\n")
    else:
        _make_link(predictable, victim, kind)
    original = predictable.read_bytes()

    proof.write(destination, overwrite=overwrite)

    assert ConnectionProof.read(destination) == proof
    assert predictable.read_bytes() == original
    assert victim.read_bytes() == b"unrelated data must survive\n"
    if kind == "symlink":
        assert predictable.is_symlink()
    elif kind == "hardlink":
        assert predictable.samefile(victim)
    assert set(tmp_path.iterdir()) == {destination, predictable, victim}


@pytest.mark.parametrize("kind", ["file", "hardlink", "symlink", "dangling_symlink"])
def test_write_refuses_existing_destination_entries(
    proof: ConnectionProof, tmp_path: Path, kind: str
) -> None:
    destination = tmp_path / "proof.json"
    victim = tmp_path / "unrelated.txt"
    if kind == "file":
        destination.write_bytes(b"existing output\n")
    else:
        if kind != "dangling_symlink":
            victim.write_bytes(b"unrelated data\n")
        _make_link(destination, victim, "symlink" if "symlink" in kind else kind)
    entries = set(tmp_path.iterdir())

    with pytest.raises(ProofFormatError, match="refusing to overwrite existing file"):
        proof.write(destination)

    assert set(tmp_path.iterdir()) == entries
    if kind == "file":
        assert destination.read_bytes() == b"existing output\n"
    elif kind == "dangling_symlink":
        assert destination.is_symlink()
        assert not victim.exists()
    else:
        assert victim.read_bytes() == destination.read_bytes() == b"unrelated data\n"
        assert destination.samefile(victim)


@pytest.mark.parametrize("kind", ["hardlink", "symlink", "dangling_symlink"])
def test_overwrite_replaces_link_without_writing_through_it(
    proof: ConnectionProof, tmp_path: Path, kind: str
) -> None:
    destination = tmp_path / "proof.json"
    victim = tmp_path / "unrelated.txt"
    if kind != "dangling_symlink":
        victim.write_bytes(b"unrelated data\n")
    _make_link(destination, victim, "symlink" if "symlink" in kind else kind)

    proof.write(destination, overwrite=True)

    assert ConnectionProof.read(destination) == proof
    assert not destination.is_symlink()
    if kind == "dangling_symlink":
        assert not victim.exists()
        assert set(tmp_path.iterdir()) == {destination}
    else:
        assert victim.read_bytes() == b"unrelated data\n"
        assert not destination.samefile(victim)
        assert set(tmp_path.iterdir()) == {destination, victim}


def test_write_refuses_destination_created_during_publication(
    proof: ConnectionProof, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "proof.json"
    link = os.link

    def racing_link(source: str | Path, target: str | Path) -> None:
        assert Path(source).parent == tmp_path
        assert Path(target) == destination
        destination.write_bytes(b"a different writer won\n")
        link(source, target)

    monkeypatch.setattr("connectcoin_p2c_tools.envelope.os.link", racing_link)

    with pytest.raises(ProofFormatError, match="refusing to overwrite existing file"):
        proof.write(destination)

    assert destination.read_bytes() == b"a different writer won\n"
    assert set(tmp_path.iterdir()) == {destination}


def test_concurrent_writers_publish_exactly_one_complete_proof(
    proof: ConnectionProof, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "proof.json"
    barrier = Barrier(4, timeout=10)
    link = os.link
    candidates = [replace(proof, input_index=index) for index in range(4)]

    def concurrent_link(source: str | Path, target: str | Path) -> None:
        barrier.wait()
        link(source, target)

    def write(candidate: ConnectionProof) -> ConnectionProof | ProofFormatError:
        try:
            candidate.write(destination)
        except ProofFormatError as exc:
            return exc
        return candidate

    monkeypatch.setattr("connectcoin_p2c_tools.envelope.os.link", concurrent_link)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(write, candidates))

    winners = [result for result in results if isinstance(result, ConnectionProof)]
    failures = [result for result in results if isinstance(result, ProofFormatError)]
    assert len(winners) == 1
    assert len(failures) == 3
    assert all("refusing to overwrite existing file" in str(exc) for exc in failures)
    assert ConnectionProof.read(destination) == winners[0]
    expected = json.dumps(winners[0].to_dict(), indent=2, sort_keys=True) + "\n"
    assert destination.read_bytes() == expected.encode("utf-8")
    assert set(tmp_path.iterdir()) == {destination}


@pytest.mark.parametrize("overwrite", [False, True])
def test_write_closes_and_syncs_private_temporary_file_before_publication(
    proof: ConnectionProof,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overwrite: bool,
) -> None:
    destination = tmp_path / "proof.json"
    named_temporary_file = tempfile.NamedTemporaryFile
    publish = os.replace if overwrite else os.link
    fsync = os.fsync
    opened: list[Any] = []
    synced: list[int] = []

    def create_temporary(**kwargs: Any) -> Any:
        temporary = named_temporary_file(**kwargs)
        opened.append(temporary)
        return temporary

    def track_fsync(descriptor: int) -> None:
        synced.append(descriptor)
        fsync(descriptor)

    def check_publication(source: str | Path, target: str | Path) -> None:
        assert len(opened) == len(synced) == 1
        assert opened[0].closed
        source = Path(source)
        assert source.parent == tmp_path
        assert source != destination.with_name(destination.name + ".tmp")
        assert ConnectionProof.read(source) == proof
        if os.name == "posix":
            assert stat.S_IMODE(source.stat().st_mode) & 0o077 == 0
        publish(source, target)

    monkeypatch.setattr(
        "connectcoin_p2c_tools.envelope.tempfile.NamedTemporaryFile", create_temporary
    )
    monkeypatch.setattr("connectcoin_p2c_tools.envelope.os.fsync", track_fsync)
    monkeypatch.setattr(
        f"connectcoin_p2c_tools.envelope.os.{'replace' if overwrite else 'link'}", check_publication
    )

    proof.write(destination, overwrite=overwrite)

    assert ConnectionProof.read(destination) == proof
    assert set(tmp_path.iterdir()) == {destination}


@pytest.mark.parametrize("stage", ["create", "write", "flush", "fsync", "publish"])
@pytest.mark.parametrize("overwrite", [False, True])
def test_write_failure_cleans_owned_temporary_file_and_preserves_existing_data(
    proof: ConnectionProof,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    overwrite: bool,
) -> None:
    destination = tmp_path / "proof.json"
    predictable = tmp_path / "proof.json.tmp"
    predictable.write_bytes(b"unrelated temporary file\n")
    if overwrite:
        destination.write_bytes(b"previous output\n")
    initial_entries = set(tmp_path.iterdir())
    named_temporary_file = tempfile.NamedTemporaryFile

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError(f"injected {stage} failure")

    def create_temporary(**kwargs: Any) -> Any:
        if stage == "create":
            fail()
        temporary = named_temporary_file(**kwargs)
        if stage in {"write", "flush"}:
            if stage == "write":
                temporary.write("partial output")
            monkeypatch.setattr(temporary, stage, fail)
        return temporary

    monkeypatch.setattr(
        "connectcoin_p2c_tools.envelope.tempfile.NamedTemporaryFile", create_temporary
    )
    if stage == "fsync":
        monkeypatch.setattr("connectcoin_p2c_tools.envelope.os.fsync", fail)
    elif stage == "publish":
        monkeypatch.setattr(
            f"connectcoin_p2c_tools.envelope.os.{'replace' if overwrite else 'link'}", fail
        )

    with pytest.raises(ProofFormatError, match=f"cannot write connection proof:.*{stage}") as exc:
        proof.write(destination, overwrite=overwrite)

    assert isinstance(exc.value.__cause__, OSError)
    assert set(tmp_path.iterdir()) == initial_entries
    assert predictable.read_bytes() == b"unrelated temporary file\n"
    if overwrite:
        assert destination.read_bytes() == b"previous output\n"
    else:
        assert not destination.exists()


def test_write_missing_parent_reports_format_error(proof: ConnectionProof, tmp_path: Path) -> None:
    with pytest.raises(ProofFormatError, match="cannot write connection proof"):
        proof.write(tmp_path / "missing" / "proof.json")
    assert not list(tmp_path.iterdir())


def test_overwrite_cleanup_does_not_remove_a_reused_staging_name(
    proof: ConnectionProof, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "proof.json"
    destination.write_bytes(b"previous output\n")
    replace_file = os.replace
    reused: list[Path] = []

    def replace_and_reuse_name(source: str | Path, target: str | Path) -> None:
        replace_file(source, target)
        staging = Path(source)
        staging.write_bytes(b"created by a different writer\n")
        reused.append(staging)

    monkeypatch.setattr("connectcoin_p2c_tools.envelope.os.replace", replace_and_reuse_name)

    proof.write(destination, overwrite=True)

    assert ConnectionProof.read(destination) == proof
    assert len(reused) == 1
    assert reused[0].read_bytes() == b"created by a different writer\n"
    assert set(tmp_path.iterdir()) == {destination, reused[0]}


def test_invalid_proof_does_not_create_temporary_file(
    proof: ConnectionProof, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "proof.json"
    destination.write_bytes(b"previous output\n")

    def unexpected_temporary(**kwargs: Any) -> None:
        pytest.fail("serialization must be validated before creating a temporary file")

    monkeypatch.setattr(
        "connectcoin_p2c_tools.envelope.tempfile.NamedTemporaryFile", unexpected_temporary
    )
    with pytest.raises(ProofFormatError, match="serialized proof"):
        replace(proof, proof=b"").write(destination, overwrite=True)

    assert destination.read_bytes() == b"previous output\n"
    assert set(tmp_path.iterdir()) == {destination}
