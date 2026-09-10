from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from connectcoin_p2c_tools.cli import main
from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.generator import GenerationOptions, GenerationResult

from .helpers import make_valid_proof


@pytest.mark.parametrize("mask, allowed", [(1, True), (2, False), (7, True)])
def test_inspect_reports_output_policy_without_claiming_crypto_or_chain_validation(
    mask: int, allowed: bool, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    envelope = replace(make_valid_proof().envelope, signature_algorithms_mask=mask)
    proof_file = tmp_path / "proof.json"
    envelope.write(proof_file)
    assert main(["inspect", str(proof_file)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["proof_version"] == 2
    assert output["signature_algorithms_mask"] == mask
    assert output["signature_scheme_allowed"] is allowed
    assert output["certificate_verify_scheme"] == "0x0403"
    assert output["cryptographic_verification_performed"] is False
    assert output["blockchain_context_verified"] is False
    assert len(output["accepted_signature_algorithms"]) == mask.bit_count()
    assert "valid" not in output


def test_inspect_rejects_legacy_envelope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    value = make_valid_proof().envelope.to_dict()
    value["version"] = 1
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert main(["inspect", str(path)]) == 1
    captured = capsys.readouterr()
    assert not captured.out
    assert "only connection proof envelope version 2" in captured.err


def _generate_args(tmp_path: Path) -> list[str]:
    return [
        "generate",
        "--domain",
        "example.com",
        "--txid",
        "11" * 32,
        "--input-index",
        "0",
        "--target",
        "ff" * 32,
        "--validation-time",
        "1800000000",
        "--roots",
        str(tmp_path / "roots.pem"),
        "--output",
        str(tmp_path / "generated.json"),
    ]


def test_generate_requires_explicit_mask(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(_generate_args(tmp_path))
    assert exc.value.code == 2
    assert "--signature-algorithms-mask" in capsys.readouterr().err


@pytest.mark.parametrize("mask", ["0", "8", "-1", "1.5", "true"])
def test_generate_rejects_invalid_mask_at_argument_parsing(mask: str, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main([*_generate_args(tmp_path), "--signature-algorithms-mask", mask])
    assert exc.value.code == 2


def test_generate_propagates_explicit_mask_and_v2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = make_valid_proof()

    def fake_generate(
        context: ConnectionProof, roots: str, options: GenerationOptions, **kwargs: object
    ) -> GenerationResult:
        assert context.version == 2
        assert context.signature_algorithms_mask == 6
        assert context.proof == b""
        assert options.connections_per_second == options.concurrency == 1
        assert roots == str(tmp_path / "roots.pem")
        # The CLI plumbing does not perform any networking in this unit test.
        return GenerationResult(replace(context, proof=fixture.envelope.proof), 1, 0.1, "127.0.0.1")

    monkeypatch.setattr("connectcoin_p2c_tools.cli.generate_connection_proof", fake_generate)
    assert main([*_generate_args(tmp_path), "--signature-algorithms-mask", "6"]) == 0
    assert json.loads(capsys.readouterr().out)["generated"] is True
    written = ConnectionProof.read(tmp_path / "generated.json")
    assert written.version == written.proof[0] == 2
    assert written.signature_algorithms_mask == 6
