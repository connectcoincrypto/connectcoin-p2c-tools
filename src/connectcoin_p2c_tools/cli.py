from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .envelope import ConnectionProof
from .errors import P2CError
from .generator import (
    GenerationOptions,
    GenerationProgress,
    generate_connection_proof,
)
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


@dataclass(slots=True)
class _ProgressPrinter:
    last_update: float = 0.0

    def __call__(self, progress: GenerationProgress) -> None:
        now = time.monotonic()
        if now - self.last_update < 1.0:
            return
        self.last_update = now
        best = progress.best_work_hash or "none"
        suffix = f" last_error={progress.last_error}" if progress.last_error else ""
        print(
            f"attempts={progress.attempts} rate={progress.attempts_per_second:.2f}/s "
            f"best={best}{suffix}",
            file=sys.stderr,
            flush=True,
        )


def _generate(args: argparse.Namespace) -> None:
    serialized_context = {
        "format": "connectcoin-p2c-proof",
        "version": 1,
        "domain": args.domain,
        "txid": args.txid,
        "input_index": args.input_index,
        "connection_work_target": args.target,
        "root_certificates_version": args.root_certificates_version,
        "validation_time": args.validation_time,
        # A one-byte placeholder lets the envelope parser validate all
        # generation context without accepting an empty serialized proof.
        "proof": "01",
    }
    context = replace(ConnectionProof.from_dict(serialized_context), proof=b"")
    options = GenerationOptions(
        port=args.port,
        connections_per_second=args.connections_per_second,
        concurrency=args.concurrency,
        connection_timeout=args.connection_timeout,
        overall_timeout=args.overall_timeout,
        max_attempts=args.max_attempts,
        allow_private_addresses=args.allow_private_addresses,
        enforce_root_pin=not args.allow_unpinned_roots,
    )
    result = generate_connection_proof(
        context,
        str(args.roots),
        options,
        progress=_ProgressPrinter(),
    )
    result.envelope.write(args.output, overwrite=args.overwrite)
    _json(
        {
            "generated": True,
            "output": str(args.output),
            "attempts": result.attempts,
            "elapsed_seconds": result.elapsed,
            "peer_ip": result.peer_ip,
        }
    )


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

    generate = subparsers.add_parser(
        "generate", help="generate a P2C proof from real TLS 1.3 connections"
    )
    generate.add_argument("--domain", required=True)
    generate.add_argument("--txid", required=True, help="final witness-independent claim txid")
    generate.add_argument("--input-index", required=True, type=int)
    generate.add_argument("--target", required=True, help="display-form connection work target")
    generate.add_argument("--root-certificates-version", type=int, default=1)
    generate.add_argument(
        "--validation-time", required=True, type=int, help="trusted ConnectCoin tip/block MTP"
    )
    generate.add_argument("--roots", required=True, type=Path, help="root certificate PEM bundle")
    generate.add_argument("--output", type=Path, default=Path("connection-proof.json"))
    generate.add_argument("--port", type=int, default=443)
    generate.add_argument(
        "--connections-per-second",
        type=int,
        default=1,
        help="aggregate start rate: 0 disables generation, -1 removes the software rate limit",
    )
    generate.add_argument("--concurrency", type=int, default=1)
    generate.add_argument("--connection-timeout", type=float, default=10.0)
    generate.add_argument(
        "--overall-timeout", type=float, default=0.0, help="seconds; 0 means no overall timeout"
    )
    generate.add_argument(
        "--max-attempts", type=int, default=0, help="0 means no attempt-count limit"
    )
    generate.add_argument("--overwrite", action="store_true")
    generate.add_argument(
        "--allow-private-addresses",
        action="store_true",
        help="unsafe development option for loopback/private targets",
    )
    generate.add_argument(
        "--allow-unpinned-roots",
        action="store_true",
        help="unsafe development option for custom root bundles",
    )
    generate.set_defaults(handler=_generate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        args.handler(args)
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130
    except (P2CError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
