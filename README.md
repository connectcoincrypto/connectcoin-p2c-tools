# ConnectCoin P2C Tools

Independent tools for ConnectCoin pay-to-connect (`PAY_TO_CONNECT`, output
type 2). This repository intentionally does not link to ConnectCoin Core or
reuse its P2C parser. The separate implementation and small test suite are
intended to detect protocol misunderstandings before a proof reaches a node.

This is early development software. It can generate and independently verify
TLS 1.3 P2C proofs, but it does not access wallets, private keys, RPC
credentials, or the P2P network.

## Current commands

```text
p2c-tools challenge --txid TXID --input-index 0
p2c-tools generate --domain example.com --txid TXID --input-index 0 --target TARGET --root-certificates-version 1 --validation-time UNIX_TIME --roots p2c_roots_v1.pem --output connection-proof.json
p2c-tools inspect connection-proof.json
p2c-tools verify connection-proof.json --roots p2c_roots_v1.pem
```

`challenge` calculates the exact 32 bytes for `ClientHello.random` from the
display-form transaction ID and input index. `inspect` performs complete P2C
v1 structural parsing and reports the transcript and work hashes. `verify`
also checks the work target, certificate path/domain/time, leaf usage, and TLS
1.3 `CertificateVerify` signature using an independent OpenSSL-backed library.
The cryptographic provider is pinned so an upgrade cannot silently change
verification behavior; upgrades require an explicit review and test run.

`generate` opens real TLS 1.3 connections with the claim challenge forced into
`ClientHello.random`, decrypts the authenticated server handshake, and searches
until the connection-work target is met. It sends no HTTP request and closes
after capturing `CertificateVerify`. By default it permits one new connection
per second with concurrency 1, rejects non-public destination addresses, pins
DNS results for the run, validates the first usable proof completely, and will
continue until success or interruption. Set `--connections-per-second -1` for
unlimited generation or `0` to explicitly disable HTTPS proof generation.
Use `--overall-timeout` and `--max-attempts` to bound a run.

The development-only switches `--allow-private-addresses` and
`--allow-unpinned-roots` weaken network and trust-bundle safety checks. They
should only be used with controlled test servers and test roots.

The JSON envelope asserts the domain, target, transaction ID, input index, and
validation time under which the proof is being checked. Until RPC/transaction
lookup is implemented, the caller must obtain those values from a trusted
ConnectCoin node and must not treat an untrusted envelope as proof of its own
blockchain context.

The trusted root file must correspond to `root_certificates_version` in the
proof envelope. Root bundle version 1 is hash-pinned to the same Mozilla bundle
as ConnectCoin Core:

```text
f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9
```

During development it can be supplied from a neighboring Core checkout:

```powershell
p2c-tools verify connection-proof.json --roots ../connectcoin/src/consensus/p2c_roots_v1.pem
```

## Development

```powershell
py -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/python.exe -m pytest
./.venv/Scripts/python.exe -m ruff check .
./.venv/Scripts/python.exe -m mypy
```

The JSON envelope is described by
`schemas/connection-proof-v1.schema.json`. The consensus witness is still only
the binary `proof` field; the surrounding JSON is an interchange format for
tools and is not serialized into a ConnectCoin transaction.

## Next milestones

1. Add durable progress/checkpoint reporting for long-running searches.
2. Add optional Core RPC orchestration. Wallet integration remains in the Core
   repository and the helper will never receive wallet private keys.
