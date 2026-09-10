from __future__ import annotations

import socket
import ssl
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.errors import ProofFormatError
from connectcoin_p2c_tools.generator import (
    GenerationError,
    GenerationOptions,
    generate_connection_proof,
    resolve_endpoints,
)
from connectcoin_p2c_tools.protocol import parse_proof
from connectcoin_p2c_tools.tls13 import (
    CONTENT_CHANGE_CIPHER_SPEC,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SIGNATURE_ALGORITHMS_CERT,
    Endpoint,
    TLSGenerationError,
    build_client_hello,
    capture_tls13_proof,
    hkdf_expand_label,
)
from connectcoin_p2c_tools.verify import verify_connection_proof

from .helpers import make_server_identity


def _client_hello_extensions(client_hello: bytes) -> dict[int, bytes]:
    # Read the TLS vectors independently of the production parser so these
    # tests catch an incorrect wire encoding as well as an incorrect policy.
    assert client_hello[0] == 1
    assert int.from_bytes(client_hello[1:4], "big") == len(client_hello) - 4
    position = 4 + 2 + 32
    position += 1 + client_hello[position]
    position += 2 + int.from_bytes(client_hello[position : position + 2], "big")
    position += 1 + client_hello[position]
    extensions_size = int.from_bytes(client_hello[position : position + 2], "big")
    position += 2
    assert len(client_hello) - position == extensions_size
    extensions = {}
    while position < len(client_hello):
        extension_type = int.from_bytes(client_hello[position : position + 2], "big")
        extension_size = int.from_bytes(client_hello[position + 2 : position + 4], "big")
        position += 4
        assert extension_type not in extensions
        extensions[extension_type] = client_hello[position : position + extension_size]
        position += extension_size
    assert position == len(client_hello)
    return extensions


@pytest.mark.parametrize(
    "mask, schemes",
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
def test_client_hello_offers_exact_output_mask(mask: int, schemes: tuple[int, ...]) -> None:
    client_hello = build_client_hello(
        "example.com",
        b"\x11" * 32,
        b"\x22" * 32,
        b"\x33" * 32,
        signature_algorithms_mask=mask,
    )
    assert client_hello[6:38] == b"\x11" * 32
    extensions = _client_hello_extensions(client_hello)
    encoded_schemes = b"".join(scheme.to_bytes(2, "big") for scheme in schemes)
    assert extensions[EXT_SIGNATURE_ALGORITHMS] == (
        len(encoded_schemes).to_bytes(2, "big") + encoded_schemes
    )
    # Issuer signatures are independent from the output's CertificateVerify
    # policy: an RSA-only output can still use an EC-signed certificate.
    assert extensions[EXT_SIGNATURE_ALGORITHMS_CERT] == bytes.fromhex(
        "00180403050306030804080508060809080a080b040105010601"
    )


def test_tls_apis_require_an_explicit_output_mask() -> None:
    endpoint = Endpoint(socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 1), "127.0.0.1")
    with pytest.raises(TypeError, match="signature_algorithms_mask"):
        build_client_hello("example.com", b"\x11" * 32, b"\x22" * 32, b"\x33" * 32)
    with pytest.raises(TypeError, match="signature_algorithms_mask"):
        capture_tls13_proof(endpoint, "example.com", b"\x11" * 32)


@pytest.mark.parametrize("mask", [None, False, True, 0, -1, 8, 255, 1.5, "7"])
def test_invalid_tls_mask_is_rejected_before_socket_creation(
    mask: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_socket(*args: object, **kwargs: object) -> None:
        pytest.fail("invalid output mask must not open a network socket")

    monkeypatch.setattr("connectcoin_p2c_tools.tls13.socket.socket", unexpected_socket)
    endpoint = Endpoint(socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 1), "127.0.0.1")
    with pytest.raises(ProofFormatError, match="signature_algorithms_mask"):
        build_client_hello(
            "example.com",
            b"\x11" * 32,
            b"\x22" * 32,
            b"\x33" * 32,
            signature_algorithms_mask=mask,
        )
    with pytest.raises(ProofFormatError, match="signature_algorithms_mask"):
        capture_tls13_proof(
            endpoint,
            "example.com",
            b"\x11" * 32,
            signature_algorithms_mask=mask,
        )


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), 0, -1])
def test_invalid_capture_timeout_is_rejected_before_socket_creation(
    timeout: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_socket(*args: object, **kwargs: object) -> None:
        pytest.fail("invalid timeout must not open a network socket")

    monkeypatch.setattr("connectcoin_p2c_tools.tls13.socket.socket", unexpected_socket)
    endpoint = Endpoint(socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 1), "127.0.0.1")
    with pytest.raises(TLSGenerationError, match="finite and positive"):
        capture_tls13_proof(
            endpoint,
            "example.com",
            b"\x11" * 32,
            signature_algorithms_mask=1,
            timeout=timeout,
        )


@pytest.mark.parametrize("mask", [None, False, True, 0, -1, 8, 255, 1.5, "7"])
def test_generator_rejects_invalid_mask_before_dns_or_workers(
    mask: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_side_effect(*args: object, **kwargs: object) -> None:
        pytest.fail("invalid generation context must be rejected before preflight or networking")

    for name in ("validate_root_bundle", "resolve_endpoints", "ThreadPoolExecutor"):
        monkeypatch.setattr(f"connectcoin_p2c_tools.generator.{name}", unexpected_side_effect)
    # Exercise the generator boundary independently of the dataclass's own
    # validation, as an external Python caller can pass a duck-typed object.
    context = cast(ConnectionProof, SimpleNamespace(signature_algorithms_mask=mask, version=2))
    with pytest.raises(ProofFormatError, match="signature_algorithms_mask"):
        generate_connection_proof(context, "unused.pem")


def test_generator_defaults_remain_rate_limited() -> None:
    options = GenerationOptions()
    assert options.connections_per_second == 1
    assert options.concurrency == 1
    assert options.allow_private_addresses is False
    assert options.enforce_root_pin is True


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
    try:
        connection, _ = listener.accept()
        connection.settimeout(3)
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


@pytest.mark.parametrize("mask", range(1, 8))
@pytest.mark.parametrize("rsa_leaf", [False, True], ids=["ecdsa", "rsae"])
def test_generator_captures_real_tls13_server_flight(
    tmp_path: Path, mask: int, rsa_leaf: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = make_server_identity(rsa_leaf=rsa_leaf)
    required_mask_bit = 2 if rsa_leaf else 1
    expected_scheme = 0x0804 if rsa_leaf else 0x0403
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
        listener.settimeout(3)
        port = listener.getsockname()[1]
        # Pin this controlled test to its IPv4 listener, independently of
        # whether the host resolver prefers ::1 for localhost.
        endpoint = Endpoint(
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            ("127.0.0.1", port),
            "127.0.0.1",
        )
        monkeypatch.setattr(
            "connectcoin_p2c_tools.generator.resolve_endpoints",
            lambda *args, **kwargs: (endpoint,),
        )
        server = threading.Thread(target=_tls_server, args=(listener, server_context), daemon=True)
        server.start()

        context = ConnectionProof(
            domain="localhost",
            txid="11" * 32,
            input_index=0,
            connection_work_target="f" * 64,
            root_certificates_version=1,
            signature_algorithms_mask=mask,
            validation_time=int(time.time()),
            proof=b"",
        )
        options = GenerationOptions(
            port=port,
            connection_timeout=2,
            overall_timeout=5,
            max_attempts=1,
            allow_private_addresses=True,
            enforce_root_pin=False,
        )
        if mask & required_mask_bit:
            result = generate_connection_proof(context, roots_path, options)
        else:
            # The server has only one leaf key type. An incompatible output
            # policy must fail negotiation, never fall back to another scheme.
            with pytest.raises(GenerationError, match="TLS peer returned alert"):
                generate_connection_proof(context, roots_path, options)
        server.join(timeout=2)

    assert not server.is_alive()
    if not mask & required_mask_bit:
        return
    assert result.peer_ip == "127.0.0.1"
    assert result.envelope.version == 2
    assert result.envelope.proof[0] == 2
    assert result.envelope.signature_algorithms_mask == mask
    parsed = parse_proof(result.envelope.proof, "localhost", result.envelope.challenge)
    assert parsed.certificate_verify_scheme == expected_scheme
    assert parsed.certificate_verify
    assert len(parsed.certificate_chain) == 1
    verified = verify_connection_proof(result.envelope, roots_path, enforce_root_pin=False)
    assert verified.certificate_verify_scheme == expected_scheme


def test_zero_connections_per_second_disables_generation() -> None:
    context = ConnectionProof(
        domain="example.com",
        txid="00" * 32,
        input_index=0,
        connection_work_target="f" * 64,
        root_certificates_version=1,
        signature_algorithms_mask=7,
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
        signature_algorithms_mask=7,
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
            capture_tls13_proof(
                endpoint,
                "localhost",
                b"\x00" * 32,
                signature_algorithms_mask=1,
                timeout=0.15,
            )
        elapsed = time.monotonic() - started
        server.join(timeout=1)

    assert elapsed < 0.4
