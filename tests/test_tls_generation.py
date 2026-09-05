from __future__ import annotations

import socket
import ssl
import threading
import time
from pathlib import Path

import pytest

from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.generator import (
    GenerationError,
    GenerationOptions,
    generate_connection_proof,
    resolve_endpoints,
)
from connectcoin_p2c_tools.protocol import parse_proof
from connectcoin_p2c_tools.tls13 import (
    CONTENT_CHANGE_CIPHER_SPEC,
    Endpoint,
    TLSGenerationError,
    capture_tls13_proof,
    hkdf_expand_label,
)
from connectcoin_p2c_tools.verify import verify_connection_proof

from .helpers import make_server_identity


def test_server_handshake_key_expansion_matches_rfc8448() -> None:
    # RFC 8448, section 3: published TLS_AES_128_GCM_SHA256 server handshake
    # traffic secret and the key/IV expanded from it.
    traffic_secret = bytes.fromhex(
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
    )
    assert hkdf_expand_label(traffic_secret, b"key", b"", 16).hex() == (
        "3fce516009c21727d0f2e4e86ee403bc"
    )
    assert hkdf_expand_label(traffic_secret, b"iv", b"", 12).hex() == ("5d313eb2671276ee13000b30")


def _tls_server(listener: socket.socket, context: ssl.SSLContext) -> None:
    connection, _ = listener.accept()
    try:
        with connection, context.wrap_socket(connection, server_side=True):
            pass
    except (ConnectionError, OSError, ssl.SSLError):
        # The P2C client intentionally closes after CertificateVerify and
        # does not complete the application-data portion of the handshake.
        pass


def _trickle_server(listener: socket.socket) -> None:
    connection, _ = listener.accept()
    with connection:
        record = bytes([CONTENT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1])
        for byte in record:
            try:
                connection.sendall(bytes([byte]))
            except OSError:
                return
            time.sleep(0.05)


def test_generator_captures_real_tls13_server_flight(tmp_path: Path) -> None:
    identity = make_server_identity()
    certificate_path = tmp_path / "server.pem"
    key_path = tmp_path / "server-key.pem"
    roots_path = tmp_path / "roots.pem"
    certificate_path.write_bytes(identity.certificate_pem)
    key_path.write_bytes(identity.private_key_pem)
    roots_path.write_bytes(identity.roots_pem)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.load_cert_chain(certificate_path, key_path)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server = threading.Thread(target=_tls_server, args=(listener, server_context), daemon=True)
        server.start()

        context = ConnectionProof(
            domain="localhost",
            txid="11" * 32,
            input_index=0,
            connection_work_target="f" * 64,
            root_certificates_version=1,
            validation_time=int(time.time()),
            proof=b"",
        )
        result = generate_connection_proof(
            context,
            str(roots_path),
            GenerationOptions(
                port=port,
                connections_per_second=-1,
                connection_timeout=2,
                overall_timeout=5,
                max_attempts=4,
                allow_private_addresses=True,
                enforce_root_pin=False,
            ),
        )
        server.join(timeout=2)

    assert not server.is_alive()
    assert result.peer_ip == "127.0.0.1"
    parsed = parse_proof(result.envelope.proof, "localhost", result.envelope.challenge)
    assert len(parsed.certificate_chain) == 1
    verify_connection_proof(result.envelope, roots_path, enforce_root_pin=False)


def test_zero_connections_per_second_disables_generation() -> None:
    context = ConnectionProof(
        domain="example.com",
        txid="00" * 32,
        input_index=0,
        connection_work_target="f" * 64,
        root_certificates_version=1,
        validation_time=1,
        proof=b"",
    )
    with pytest.raises(GenerationError, match="disabled"):
        generate_connection_proof(
            context,
            "unused.pem",
            GenerationOptions(connections_per_second=0),
        )


@pytest.mark.parametrize(
    "options, message",
    [
        (GenerationOptions(connection_timeout=float("nan")), "connection_timeout"),
        (GenerationOptions(overall_timeout=float("inf")), "overall_timeout"),
        (GenerationOptions(concurrency=257), "concurrency"),
    ],
)
def test_invalid_generation_limits_are_rejected(options: GenerationOptions, message: str) -> None:
    context = ConnectionProof(
        domain="example.com",
        txid="00" * 32,
        input_index=0,
        connection_work_target="f" * 64,
        root_certificates_version=1,
        validation_time=1,
        proof=b"",
    )
    with pytest.raises(GenerationError, match=message):
        generate_connection_proof(context, "unused.pem", options)


def test_private_addresses_are_blocked_by_default() -> None:
    with pytest.raises(GenerationError, match="no permitted TCP addresses"):
        resolve_endpoints("localhost", 443)


def test_connection_timeout_is_a_hard_handshake_deadline() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server = threading.Thread(target=_trickle_server, args=(listener,), daemon=True)
        server.start()
        endpoint = Endpoint(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, ("127.0.0.1", port), "127.0.0.1"
        )
        started = time.monotonic()
        with pytest.raises((OSError, TLSGenerationError)):
            capture_tls13_proof(endpoint, "localhost", b"\x00" * 32, timeout=0.15)
        elapsed = time.monotonic() - started
        server.join(timeout=1)

    assert elapsed < 0.4
