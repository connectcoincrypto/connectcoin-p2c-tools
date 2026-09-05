from __future__ import annotations

import ipaddress
import math
import socket
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from .envelope import ConnectionProof
from .errors import P2CError, ProofFormatError, ProofVerificationError
from .hashes import internal_hash_to_display, meets_work_target
from .protocol import parse_proof
from .tls13 import Endpoint, TLSGenerationError, TLSProofMessages, capture_tls13_proof
from .verify import validate_root_bundle, verify_connection_proof


class GenerationError(P2CError):
    """A P2C proof could not be generated under the requested limits."""


@dataclass(frozen=True, slots=True)
class GenerationOptions:
    port: int = 443
    connections_per_second: int = 1
    concurrency: int = 1
    connection_timeout: float = 10.0
    overall_timeout: float = 0.0
    max_attempts: int = 0
    allow_private_addresses: bool = False
    enforce_root_pin: bool = True


@dataclass(frozen=True, slots=True)
class GenerationProgress:
    attempts: int
    elapsed: float
    attempts_per_second: float
    best_work_hash: str | None
    last_error: str | None


@dataclass(frozen=True, slots=True)
class GenerationResult:
    envelope: ConnectionProof
    attempts: int
    elapsed: float
    peer_ip: str


ProgressCallback = Callable[[GenerationProgress], None]
MAX_CONCURRENCY = 256


def _validate_options(options: GenerationOptions) -> None:
    if not 1 <= options.port <= 65535:
        raise GenerationError("port must be between 1 and 65535")
    if options.connections_per_second < -1:
        raise GenerationError("connections_per_second must be -1, 0, or a positive integer")
    if options.connections_per_second == 0:
        raise GenerationError("TLS proof generation is disabled by connections_per_second=0")
    if not 1 <= options.concurrency <= MAX_CONCURRENCY:
        raise GenerationError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
    if not math.isfinite(options.connection_timeout) or options.connection_timeout <= 0:
        raise GenerationError("connection_timeout must be finite and positive")
    if not math.isfinite(options.overall_timeout) or options.overall_timeout < 0:
        raise GenerationError("overall_timeout must be finite and non-negative")
    if options.max_attempts < 0:
        raise GenerationError("max_attempts must not be negative")


def resolve_endpoints(
    domain: str, port: int, *, allow_private: bool = False
) -> tuple[Endpoint, ...]:
    try:
        addresses = socket.getaddrinfo(
            domain,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise GenerationError(f"DNS resolution failed for {domain}: {exc}") from exc
    result: list[Endpoint] = []
    seen: set[tuple[int, str]] = set()
    rejected: list[str] = []
    for family, socket_type, protocol, _, address in addresses:
        ip_text = str(address[0]).split("%", maxsplit=1)[0]
        try:
            parsed_ip = ipaddress.ip_address(ip_text)
        except ValueError:
            rejected.append(ip_text)
            continue
        if not allow_private and not parsed_ip.is_global:
            rejected.append(ip_text)
            continue
        identity = (family, str(address))
        if identity in seen:
            continue
        seen.add(identity)
        result.append(Endpoint(family, socket_type, protocol, address, ip_text))
    if not result:
        detail = f"; rejected addresses: {', '.join(sorted(set(rejected)))}" if rejected else ""
        raise GenerationError(f"domain resolved to no permitted TCP addresses{detail}")
    return tuple(result)


def _capture(
    endpoint: Endpoint,
    envelope: ConnectionProof,
    connection_timeout: float,
) -> TLSProofMessages:
    return capture_tls13_proof(
        endpoint,
        envelope.domain,
        envelope.challenge,
        timeout=connection_timeout,
    )


def generate_connection_proof(
    context: ConnectionProof,
    roots_path: str | Path,
    options: GenerationOptions | None = None,
    progress: ProgressCallback | None = None,
) -> GenerationResult:
    """Search real TLS connections until one satisfies the P2C work target."""
    if options is None:
        options = GenerationOptions()
    _validate_options(options)
    if context.proof:
        raise GenerationError("generation context must have an empty proof field")
    try:
        datetime.fromtimestamp(context.validation_time, UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise GenerationError("validation_time cannot be represented") from exc
    validate_root_bundle(
        roots_path,
        context.root_certificates_version,
        enforce_root_pin=options.enforce_root_pin,
    )
    endpoints = resolve_endpoints(
        context.domain, options.port, allow_private=options.allow_private_addresses
    )
    started_at = time.monotonic()
    next_start = started_at
    attempts_started = 0
    attempts_completed = 0
    next_endpoint = 0
    best_value: int | None = None
    best_hash: str | None = None
    last_error: str | None = None
    preflight_complete = False
    pending: dict[Future[TLSProofMessages], int] = {}

    executor = ThreadPoolExecutor(max_workers=options.concurrency, thread_name_prefix="p2c-tls")
    try:
        while True:
            now = time.monotonic()
            elapsed = now - started_at
            if options.overall_timeout and elapsed >= options.overall_timeout:
                raise GenerationError(
                    f"generation timed out after {attempts_completed} completed attempts"
                )
            if options.max_attempts and attempts_started >= options.max_attempts and not pending:
                detail = f"; last error: {last_error}" if last_error else ""
                raise GenerationError(
                    f"no proof met the target in {attempts_completed} attempts{detail}"
                )

            while len(pending) < options.concurrency:
                if options.max_attempts and attempts_started >= options.max_attempts:
                    break
                now = time.monotonic()
                if options.connections_per_second != -1 and now < next_start:
                    break
                endpoint = endpoints[next_endpoint % len(endpoints)]
                next_endpoint += 1
                attempts_started += 1
                attempt_timeout = options.connection_timeout
                if options.overall_timeout:
                    attempt_timeout = min(
                        attempt_timeout,
                        options.overall_timeout - (now - started_at),
                    )
                future = executor.submit(_capture, endpoint, context, attempt_timeout)
                pending[future] = attempts_started
                if options.connections_per_second != -1:
                    interval = 1.0 / options.connections_per_second
                    next_start = max(next_start + interval, now + interval)

            if not pending:
                delay = max(0.0, next_start - time.monotonic())
                time.sleep(min(delay, 0.05))
                continue

            wait_timeout = 0.05
            if len(pending) < options.concurrency and options.connections_per_second != -1:
                wait_timeout = min(wait_timeout, max(0.0, next_start - time.monotonic()))
            done, _ = wait(pending, timeout=wait_timeout, return_when=FIRST_COMPLETED)
            for future in done:
                pending.pop(future)
                attempts_completed += 1
                try:
                    capture = future.result()
                    candidate = replace(context, proof=capture.encoded_proof)
                    parsed = parse_proof(candidate.proof, candidate.domain, candidate.challenge)
                    numeric_work = int.from_bytes(parsed.connection_work_hash, "little")
                    if best_value is None or numeric_work < best_value:
                        best_value = numeric_work
                        best_hash = internal_hash_to_display(parsed.connection_work_hash)

                    candidate_verified = False
                    if not preflight_complete:
                        preflight = replace(candidate, connection_work_target="f" * 64)
                        verify_connection_proof(
                            preflight,
                            roots_path,
                            enforce_root_pin=options.enforce_root_pin,
                        )
                        preflight_complete = True
                        candidate_verified = True

                    if meets_work_target(
                        parsed.connection_work_hash, candidate.connection_work_target
                    ):
                        if not candidate_verified:
                            verify_connection_proof(
                                candidate,
                                roots_path,
                                enforce_root_pin=options.enforce_root_pin,
                            )
                        elapsed = time.monotonic() - started_at
                        return GenerationResult(
                            candidate, attempts_completed, elapsed, capture.peer_ip
                        )
                    last_error = None
                except (
                    OSError,
                    TLSGenerationError,
                    ProofFormatError,
                    ProofVerificationError,
                ) as exc:
                    last_error = str(exc)

            if progress is not None and attempts_completed:
                elapsed = time.monotonic() - started_at
                progress(
                    GenerationProgress(
                        attempts=attempts_completed,
                        elapsed=elapsed,
                        attempts_per_second=attempts_completed / elapsed if elapsed else 0.0,
                        best_work_hash=best_hash,
                        last_error=last_error,
                    )
                )
    finally:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
