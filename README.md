# ConnectCoin P2C Tools

Independent tools for ConnectCoin pay-to-connect (`PAY_TO_CONNECT`, output
type 2). This repository intentionally does not link to ConnectCoin Core or
reuse its P2C parser. The separate implementation and small test suite are
intended to detect protocol misunderstandings before a proof reaches a node.

This is early development software. It can generate and independently verify
TLS 1.3 P2C proofs, but it does not access wallets, private keys, RPC
credentials, or the P2P network.

## Protocol compatibility

Version **0.3.0** supports **P2C proof v2 only**, including the mandatory
per-output `signature_algorithms_mask` introduced by Core's signature-mask
test-network reset. The implementation was checked against ConnectCoin Core
[`994835a402665ddf687348d394bc9ba6c446b1de`](https://github.com/connectcoincrypto/connectcoin/commit/994835a402665ddf687348d394bc9ba6c446b1de),
including protocol changes in `6f86ce2727` and `d4d1ae56aa`.

Old binary v1 proofs and JSON envelope v1 are rejected. Obtain fresh claim
context from the updated node and regenerate proofs; do not just relabel an
old file. There is no default or fallback signature mask. This standalone tool
does not maintain network/genesis metadata, peers, a wallet, or a chain index:
make sure the node supplying the claim context is on the intended current chain.

The consensus witness is byte `02` followed by five complete TLS handshake
messages: ClientHello, ServerHello, EncryptedExtensions, Certificate, and
CertificateVerify. The v2 work hash is:

```text
TaggedHash("ConnectCoin/P2C/work/v2", ClientHello || ServerHello || EncryptedExtensions || Certificate)
```

All four handshake headers are included. The proof version byte and **all** of
CertificateVerify (header, scheme, signature length, and signature) are excluded
from work. CertificateVerify is still mandatory and its signature is verified.
The ordinary TLS transcript hash covers the same four messages. Work hashes
use Core's uint256 display order; transcript hashes use TLS digest order.

The claim challenge tag remains `ConnectCoin/P2C/claim/v1`; that tag is unrelated
to the proof version. Immutable root bundle version 1 also remains unchanged.

### Output signature policy

The mask is an integer from 1 to 7, combining these bits:

| Bit | TLS SignatureScheme | Name |
| --- | --- | --- |
| 1 | `0x0403` | `ecdsa_secp256r1_sha256` |
| 2 | `0x0804` | `rsa_pss_rsae_sha256` |
| 4 | `0x0809` | `rsa_pss_pss_sha256` |

For example, mask 6 permits both RSA-PSS schemes but not ECDSA; mask 7 permits
all three. Use the actual output's mask, not whichever value permits a proof
you already have. Generation offers exactly that mask in ClientHello's
`signature_algorithms`. `signature_algorithms_cert` remains a separate offer
for certificate issuer signatures. Verification checks the selected
CertificateVerify scheme against the output mask, not every ClientHello offer.

ECDSA requires a P-256 leaf key. RSA-PSS requires at least 2048 bits, SHA-256,
MGF1-SHA-256, and a 32-byte signature salt. RSAE and PSS leaf SPKI encodings are
distinguished; restricted PSS keys must permit those parameters.

Every RSA public key in supplied certificates and trusted roots, including
RSAE, RSA-PSS, intermediates and unused chain entries, must have a public
exponent of at most **64 bits** (`e <= 2^64 - 1`), independently of modulus size.
Verification rejects larger exponents before certificate-path or TLS-signature
verification. Generation checks this limit as soon as it receives the TLS
Certificate message, before waiting for CertificateVerify. This changes
certificate acceptance, not the proof format or immutable root bundle; use
an updated Core node with the same rule.

## Current commands

```text
p2c-tools challenge --txid TXID --input-index 0
p2c-tools generate --domain example.com --txid TXID --input-index 0 --target TARGET --root-certificates-version 1 --signature-algorithms-mask MASK --validation-time UNIX_TIME --roots p2c_roots_v1.pem --output connection-proof.json
p2c-tools inspect connection-proof.json
p2c-tools verify connection-proof.json --roots p2c_roots_v1.pem
```

`challenge` calculates the exact 32 bytes for `ClientHello.random` from the
display-form transaction ID and input index. `inspect` performs complete P2C
v2 structural parsing and reports the transcript/work hashes, accepted
signature algorithms, and whether the selected scheme is allowed. It does
**not** authenticate the certificates or TLS signature. `verify`
also checks the work target, certificate path/domain/time, leaf usage, and TLS
1.3 `CertificateVerify` signature using an independent OpenSSL-backed library.
The cryptographic provider is pinned so an upgrade cannot silently change
verification behavior; upgrades require an explicit review and test run.
The current pin is `cryptography==50.0.1`, including the fixes for duplicate
certificate path growth ([GHSA-jwv3-5hgf-82ww](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww))
and wildcard DNS name-constraint bypass ([GHSA-m2h6-j472-rp4c](https://github.com/pyca/cryptography/security/advisories/GHSA-m2h6-j472-rp4c)).
Its official binary wheels include OpenSSL 4.0.2; source builds use their linked
OpenSSL. Existing installations must reinstall the project to receive the
updated provider. The proof format and immutable root bundle are unchanged.

`--signature-algorithms-mask` is required for generation; replace `MASK` with
the on-chain value. The other uppercase placeholders must also be replaced
with trusted claim data. CLI inspection/verification reports
`blockchain_context_verified: false`: even a cryptographically valid proof is
not evidence that the asserted output exists, is unspent, or will be accepted
by a node. The independent OpenSSL-backed X.509 policy is not a replacement
for Core's consensus implementation; submit through Core for authoritative
validation.
For example, the pinned provider rejects an explicitly encoded DEFAULT
`saltLength=20` in PSS parameters, whereas Core's parser may accept that encoding.
The stricter DER policy can therefore reject some certificates independently
of their mathematical signature validity.

`generate` opens real TLS 1.3 connections with the claim challenge forced into
`ClientHello.random`, decrypts the authenticated server handshake, and searches
until the connection-work target is met. It sends no HTTP request and closes
after capturing `CertificateVerify`. By default it permits one new connection
per second with concurrency 1, rejects non-public destination addresses, pins
DNS results for the run, validates the first usable proof completely, and will
continue until success or interruption. Set `--connections-per-second -1` for
unlimited generation or `0` to explicitly disable HTTPS proof generation.
Use `--overall-timeout` and `--max-attempts` to bound a run.
Concurrency remains opt-in (default 1, maximum 256) in this standalone tool;
changes to Core's automatic-claim worker defaults do not raise these limits.

Proof files are staged in exclusively created, randomly named temporary files
in the output directory, then published only after the complete write is closed.
Without `--overwrite`, publication atomically refuses an existing destination,
including a symbolic link or a file created by another writer during generation.
This mode requires filesystem hard-link support (for example, NTFS, APFS or
ext4); unsupported filesystems fail rather than falling back to a racy overwrite.
With `--overwrite`, the completed file replaces the destination entry atomically,
not the contents of a file reached through a destination link. Use an output
directory you control; preexisting `OUTPUT.tmp` files are never reused or removed.

The development-only switches `--allow-private-addresses` and
`--allow-unpinned-roots` weaken network and trust-bundle safety checks. They
should only be used with controlled test servers and test roots.

The JSON envelope asserts the domain, target, output signature mask,
transaction ID, input index, and validation time under which the proof is
being checked. Until RPC/transaction
lookup is implemented, the caller must obtain those values from a trusted
ConnectCoin node and must not treat an untrusted envelope as proof of its own
blockchain context.

An updated Core wallet's `preparep2cclaim` RPC returns `txid`, `input_index`,
`clienthello_random`, `domain`, `connection_work_target`,
`root_certificates_version`, `signature_algorithms_mask`, and `validation_time`.
Use the prepared **spending/claim transaction's txid**, not the funding txid;
the challenge binds its final non-witness transaction and input index. Keep
the prepared transaction, destination, and fees unchanged during generation.
Use the chain's median time past, not the local clock. Core rechecks time,
proof validity, and bounty availability when submitting; generation here
never submits or broadcasts anything automatically.

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

Ubuntu (Python 3.11 or newer):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
```

Windows PowerShell:

```powershell
py -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/python.exe -m pytest
./.venv/Scripts/python.exe -m ruff check .
./.venv/Scripts/python.exe -m ruff format --check .
./.venv/Scripts/python.exe -m mypy
```

The JSON envelope is described by
`schemas/connection-proof-v2.schema.json`. Its `version` is 2 and
`signature_algorithms_mask` is mandatory, including when calling the Python
`ConnectionProof` constructor directly. The consensus witness is still only
the binary `proof` field; the surrounding JSON is an interchange format for
tools and is not serialized into a ConnectCoin transaction.

Tests are offline, apart from controlled loopback TLS servers. They cover all
seven masks, v1 rejection, v2 work vectors, CertificateVerify independence
from work, actual TLS signature verification, and generator negotiation.
Security regressions verify complete signed proofs with local test CAs:
constrained DNS wildcards and duplicate certificate chains at the eight-certificate
limit. The duplicate-chain rejection runs in a subprocess with a five-second
deadline so a path-building regression cannot stall the suite.
`vectors/challenge-v1.json` remains valid because the claim tag is unchanged;
`vectors/work-v2.json` is a synthetic structural vector, not a trusted TLS proof.

## Next milestones

1. Add durable progress/checkpoint reporting for long-running searches.
2. Add optional Core RPC orchestration. Wallet integration remains in the Core
   repository and the helper will never receive wallet private keys.
