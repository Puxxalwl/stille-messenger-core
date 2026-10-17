# stille-messenger

<p align="center">
  <img src="docs/assets/stille_logo.png" alt="stille-messenger logo" width="280">
</p>

> **Legacy compatibility:** the data directory `~/.shopot`, invitation prefixes,
> discovery marker and cryptographic domain strings retain their original values.
> Existing identities, encrypted history and protocol formats are unchanged.

**English** | [Русский](docs/ru/README.md)

Serverless P2P messenger core: **zero servers of our own**, message history
lives on the two devices only. Implementation: pure Zig, std-only — no
packages, no OS dependencies. Source: [`core/`](core/).

The C++ version (v0.2.4, FTXUI/MQTT/WebRTC) is removed from master; the
archive lives under the tag `cpp-archive`.

## Feature set

| Area | What the core does |
|---|---|
| Identity | X25519 + Ed25519 keypairs derived from one 32-byte seed (`~/.shopot/zig-seed`, 0600) |
| Transport | Direct TCP (ports 7777–7786) or self-hosted relay; persistent relay presence (reconnects without a new invite); LAN discovery over UDP multicast; wire disguised as TLS 1.3 |
| Encryption | XX-like handshake, AEAD transport, double ratchet with post-compromise security (epoch rotation every 256 messages) |
| Messaging | Telegram-style formatting entities (bold/italic/spoiler/code/link), offline delivery (encrypted outbox, ACKs, dedup), reactions, 16 kHz E2EE voice calls (ADPCM, DTX), resumable file transfer |
| Storage | Append-only AEAD log — zero plaintext bytes on disk |
| Interface | Binary framed UDS API (`~/.shopot/api.sock`) — the only interface; GUI clients render, the core does everything else |

## Build

Requires [Zig 0.17.0](https://ziglang.org/download/) only.

```bash
make            # = cd core && zig build -Doptimize=ReleaseFast
make test       # = cd core && zig build test --summary all
```

Binary: `core/zig-out/bin/stille-messenger`. Release builds for
x86_64-linux-musl and aarch64-macos are attached to every `zig-v*` tag.

## Running

```bash
stille-messenger init          # identity: ~/.shopot/zig-seed (0600)
stille-messenger serve         # daemon: core + UDS API (~/.shopot/api.sock)
```

There is no CLI/TUI: the only client interface is the GUI, which talks to
the core over UDS using the binary framed protocol (typed responses,
machine error codes, events). Specification for client authors:
[`core/docs/CORE-API.md`](core/docs/CORE-API.md) (API 2.0.0).

Adding a friend is one action: `CREATE_INVITE` produces a one-way code
(`shopot://i/...`); the holder performs a single `ACCEPT_INVITE`. The
contact, session and delivery are established by the core itself (LAN
discovery, autodial, offline outbox, delivery ACKs).

## Relay (IP hiding)

```bash
# on any server (VPS):
./stille-messenger relay 0.0.0.0:9000

# on your side:
> invite bob relay vps.example.com:9000
# → the code goes to bob; bob accepts it and sees only the relay address
```

## Cryptography

- XX-like handshake (X25519 + Ed25519, transcript signatures, remote-static
  verification)
- Double encryption of messages: ratchet chains on top of an AEAD stream
- Payloads ≥ 512 bytes are zlib-compressed inside the sealed layer
  (compression flag authenticated with the frame)
- Calls: 20 ms frames, per-frame key = HKDF(call_secret, seq), own AEAD
  transport
- Storage: append-only AEAD log, not a single plaintext byte

Details: [`core/docs/PROTOCOL.md`](core/docs/PROTOCOL.md),
[SECURITY.md](SECURITY.md).

## Documentation

| Document | Content |
|---|---|
| [`core/docs/CORE-API.md`](core/docs/CORE-API.md) / [ru](core/docs/ru/CORE-API.md) | binary UDS interface for GUI clients (API 2.0.0) |
| [`core/docs/PROTOCOL.md`](core/docs/PROTOCOL.md) / [ru](core/docs/ru/PROTOCOL.md) | byte-level wire protocol v4 |
| [`core/docs/ARCHITECTURE.md`](core/docs/ARCHITECTURE.md) / [ru](core/docs/ru/ARCHITECTURE.md) | layers, data flow, threading |
| [`core/docs/ROADMAP.md`](core/docs/ROADMAP.md) / [ru](core/docs/ru/ROADMAP.md) | technical plan and anti-plan |
| [SECURITY.md](SECURITY.md) / [ru](docs/ru/SECURITY.md) | threat model, reporting, crypto inventory |
| [CONTRIBUTING.md](CONTRIBUTING.md) / [ru](docs/ru/CONTRIBUTING.md) | contribution rules (kernel-style) |
| [docs/DOCSTYLE.md](docs/DOCSTYLE.md) / [ru](docs/ru/DOCSTYLE.md) | binding rules for writing documentation |

## Official client

- Second project developer: [EryyynIT](https://github.com/EryyynIT)
- Official stille-messenger client: [stille-messenger](https://github.com/EryyynIT/stille-messenger)

## License

MIT — see [LICENSE](LICENSE).
