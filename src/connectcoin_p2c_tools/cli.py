from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from .envelope import ConnectionProof
from .errors import P2CError
from .hashes import claim_challenge, internal_hash_to_display, meets_work_target
from .protocol import parse_proof
from .verify import verify_connection_proof


def _json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _challenge(args: argparse.Namespace) -> None:
    challenge = claim_challenge(args.txid, args.input_index)
    _json(
        {
            "txid": args.txid,
            "input_index": args.input_index,
            "clienthello_random": challenge.hex(),
        }
    )


def _inspect(args: argparse.Namespace) -> None:
    envelope = ConnectionProof.read(args.proof_file)
    parsed = parse_proof(envelope.proof, envelope.domain, envelope.challenge)
    _json(
        {
            "valid_structure": True,
            "domain": envelope.domain,
            "txid": envelope.txid,
            "input_index": envelope.input_index,
            "challenge": envelope.challenge.hex(),
            "transcript_hash": parsed.transcript_hash.hex(),
            "connection_work_hash": internal_hash_to_display(parsed.connection_work_hash),
            "meets_work_target": meets_work_target(
                parsed.connection_work_hash, envelope.connection_work_target
            ),
            "certificate_count": len(parsed.certificate_chain),
            "certificate_verify_scheme": f"0x{parsed.certificate_verify_scheme:04x}",
            "message_sizes": {
                "client_hello": len(parsed.client_hello),
                "server_hello": len(parsed.server_hello),
                "encrypted_extensions": len(parsed.encrypted_extensions),
                "certificate": len(parsed.certificate),
                "certificate_verify": len(parsed.certificate_verify),
            },
            "proof_size": len(envelope.proof),
        }
    )


def _verify(args: argparse.Namespace) -> None:
    envelope = ConnectionProof.read(args.proof_file)
    result = verify_connection_proof(envelope, args.roots)
    output = asdict(result)
    output["valid"] = True
    output["certificate_verify_scheme"] = f"0x{result.certificate_verify_scheme:04x}"
    _json(output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="p2c-tools", description="Independent ConnectCoin pay-to-connect proof tools"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    challenge = subparsers.add_parser(
        "challenge", help="calculate the ClientHello.random claim challenge"
    )
    challenge.add_argument("--txid", required=True, help="display-form transaction id")
    challenge.add_argument("--input-index", required=True, type=int)
    challenge.set_defaults(handler=_challenge)

    inspect = subparsers.add_parser("inspect", help="parse a proof without X.509 validation")
    inspect.add_argument("proof_file", type=Path)
    inspect.set_defaults(handler=_inspect)

    verify = subparsers.add_parser(
        "verify", help="fully verify a proof against a pinned root bundle"
    )
    verify.add_argument("proof_file", type=Path)
    verify.add_argument("--roots", required=True, type=Path, help="root certificate PEM bundle")
    verify.set_defaults(handler=_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        args.handler(args)
    except (P2CError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
