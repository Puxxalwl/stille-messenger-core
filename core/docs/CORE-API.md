# CORE-API — stille-messenger core binary interface

Technical specification for GUI client authors. Russian version:
[ru/CORE-API.md](ru/CORE-API.md).

The core (the `stille-messenger-core serve` daemon) owns the cryptography, contacts,
sessions, and delivery. A client connects over a Unix domain socket and
renders. The protocol is **binary**: no strings-as-protocol, no JSON, no
human-readable text on the wire — only typed byte frames and machine-readable
codes (methods, statuses, events).

- API version: **2.9.0** (returned by `GET_VERSION`, semver).
  2.9.0 adds NAT traversal for relayed peers (config bit6 `nat_punch`,
  §4.9; the ROUTE_STATE event, §5) — the relay session upgrades to a
  direct punched connection (PROTOCOL.md §15.1), relay stays the fallback.
  2.8.0 added short identity codes for deeplinks (§4.2:
  `GENERATE_SHORT_CODE`/`DECODE_SHORT_CODE`) — pure local computation,
  no wire or storage change.
  2.7.0 adds one-key friend-request invites, observable connection state,
  contact snapshots/deltas, endpoint discovery, hybrid invite codes and
  paged history (§4.2, §4.11), without peer wire or storage migration.
  2.6.0 adds account recovery (§4.10: `CREATE_RECOVERY_BACKUP`/
  `RESTORE_RECOVERY_BACKUP`, statuses `BAD_RECOVERY`/`NOT_INITIALIZED`/
  `ALREADY_PROVISIONED`) and the unprovisioned serve mode. History: 2.5.0 —
  `GET_MY_AVATAR` (§4.4);
  2.0.0 — formatting-entities tail in message payloads (§4.3); 2.1.0 —
  `SEARCH_MESSAGE`/`GLOBAL_SEARCH_MESSAGE` (§4.3); 2.2.0 — chat pinning/
  deletion, message pinning, contact-card sharing (§4.8), the
  `CONTACT_CARD` event, and the honest `delivered` bit (§7); 2.3.0 —
  message replies and reactions (§4.3); 2.4.0 — core configuration
  (§4.9: `GET_CONFIG`/`SET_CONFIG`, `CONFIG_CHANGED`), the client
  database (§4.9: `WRITE_DB`/`READ_DB`/`DELETE_DB`), device sync, and
  the `TOR_UNAVAILABLE` status.
- Normative wire protocol: [PROTOCOL.md](PROTOCOL.md).

## 1. Model

| Entity | Definition |
|---|---|
| core | the `stille-messenger-core serve` process. One user = one daemon = one `$HOME`; several users on a machine use different `$HOME`s |
| client | any process connected to `$HOME/.stille-messenger/api.sock` (UDS, mode 0700). Multiple concurrent connections are allowed; events are broadcast to all |
| contact | the conversation peer, identified by its bundle (`enc_pk‖sign_pk`, 64 bytes). In this API a contact is an integer `cid` (u32), stable within a given `$HOME`: 1..N in order of addition |
| msg_id | 16 random bytes identifying a message globally; used for reactions, statuses, `GET_MESSAGE` |

The core has no TUI/CLI: the daemon has no interactive input; all control
flows through this API.

### One user action maximum

The core owns: introductions (JOIN protocol), address discovery (LAN
multicast, autodial), offline delivery (outbox + ACK), reconnection,
presence. For the user, any scenario is zero or one action (paste an invite
code). A client must not ask for confirmations, addresses, or an ordering of
steps — the core has already handled them.

### What the core does NOT do

- UI, rendering, emoji glyphs, QR — client's job.
- Third-party storage — there is none; content lives on the two devices only
  (the encrypted log is local). The recovery package (§4.10) is the one
  deliberate exception in kind: a sealed, client-stored blob in the user's
  own cloud holding identity/profile (never message content).
- NAT traversal is now built in for relayed pairs (2.9.0, §4.9 bit6):
  both peers behind NAT upgrade their relay session to a direct punched
  connection (PROTOCOL.md §15.1). The remaining honest gap: two NAT-ed
  peers with **no** relay and no LAN channel cannot meet at all —
  rendezvous itself needs the relay; symmetric NATs are not punched
  (the pair silently stays relayed).
- Parsing pictures/files: bytes are passed as-is.

## 2. Frame

All integers are little-endian. The header of every frame is exactly 16 bytes:

| Field | Type | Offset | Meaning |
|---|---|---|---|
| magic | u16 | 0..2 | `0x5A50` ("ZP") |
| version | u8 | 2 | `1` |
| kind | u8 | 3 | `1` = REQUEST, `2` = RESPONSE, `3` = EVENT |
| id | u16 | 4..6 | method (REQUEST/RESPONSE) or event (EVENT) |
| request_id | u32 | 6..10 | correlation: set by the client, echoed by the core in RESPONSE; `0` in EVENT |
| status | u16 | 10..12 | status code (RESPONSE only; `0` otherwise) |
| payload_len | u32 | 12..16 | payload length, `0..16777216` (16 MiB) |

- Exactly one REQUEST yields exactly one RESPONSE with the same `id` and
  `request_id`.
- Payload over 16 MiB → `TOO_BIG` and the connection is dropped.
- Broken magic/version, or a non-REQUEST frame from a client → `BAD_FRAME`
  and the connection is closed (stream resynchronization is impossible).
- There are no text fields. Strings are `str16` = `[len u16][bytes]` and
  `str32` = `[len u32][bytes]` (raw UTF-8 bytes, no terminator).
- Extra or missing bytes in a method payload → `BAD_FRAME` (strict parsing).
- `CLOSE` closes the connection (not the daemon).

## 3. Status codes

Names are the contract. There is and will be no human-readable text in
responses.

| Code | Name | When |
|---|---|---|
| 0 | `OK` | success |
| 1 | `BAD_FRAME` | frame/payload not parsed (magic, version, length, structure) |
| 2 | `UNKNOWN_METHOD` | unknown method id |
| 3 | `BAD_ARGS` | invalid/incomplete argument values |
| 4 | `NO_CONTACT` | cid does not exist |
| 5 | `CONTACT_BLOCKED` | contact is blocked locally |
| 6 | `NOT_FOUND` | object not found (message by msg_id) |
| 7 | `TOO_BIG` | size limit exceeded (body, avatar, frame, history) |
| 8 | `BAD_INVITE_CODE` | invite code not parsed/recognized |
| 9 | `TOO_MANY_INVITES` | invite registry full (4 live) |
| 10 | `FILE_NOT_FOUND` | file at path not found/not readable |
| 11 | `UNSUPPORTED_REACTION` | reaction codepoint outside U+0000..U+10FFFF |
| 12 | `NO_SESSION` | no live session with the contact (required for the operation) |
| 13 | `BUSY` | line is busy (a call is already active) |
| 14 | `NO_CALL` | no active call |
| 15 | `NO_RELAY` | relay unreachable |
| 16 | `TRANSPORT_FAILED` | transport did not come up (dial/handshake) |
| 17 | `TOR_UNAVAILABLE` | Tor SOCKS5 proxy unreachable (`use_tor_mask` on) |
| 18 | `BAD_RECOVERY` | recovery blob unusable: not parsed, wrong unlock secret, unknown format version (§4.10) |
| 19 | `NOT_INITIALIZED` | no profile: daemon runs unprovisioned (§4.10); `GET_IDENTITY` and `CREATE_RECOVERY_BACKUP` refuse |
| 20 | `ALREADY_PROVISIONED` | profile already exists: `RESTORE_RECOVERY_BACKUP` requires an empty profile (§4.10) |
| 255 | `INTERNAL` | internal core error |

## 4. Methods (REQUEST)

Names are the contract; values are stable. "∅" — empty payload.

### 4.1 Service

| Method | id | Payload | Response (payload at OK) |
|---|---|---|---|
| `GET_VERSION` | 2 | ∅ | `[major u16][minor u16][patch u16]` |
| `GET_IDENTITY` | 3 | ∅ | `[bundle 64][fingerprint 32]` — BLAKE2s-256(bundle), raw bytes |
| `CLOSE` | 1 | ∅ | ∅, then the core closes the connection |

`GET_VERSION` is the readiness probe: connect → `GET_VERSION` → proceed.
A major bump means this document's contract changed (see CHANGELOG).

### 4.2 Contacts

#### `CREATE_INVITE` (4)
Creates a one-key friend request. Payload: `[flags u8 (bit0 = relay)][name str16 ≤ 32][addr str16]`.
- Empty name → `stille-messenger`. `addr` is `host:port` (optional: otherwise the holder
  discovers the inviter via the LAN announcement). `relay=1` requires `addr`;
  the connection goes through a relay — the peer never sees your IP.
- The secret is one-time: burned by the first valid JOIN. Registry: up to 4
  live invites in daemon memory (a restart invalidates the codes).

Response: `[code str16]` — the one-way invite code (URL
`stille://i/...`, transferable over any messenger; legacy `shopot://i/...`
and v1 codes `shopot1.` are also accepted).
Errors: `TOO_MANY_INVITES`, `BAD_ARGS`.

#### `ACCEPT_INVITE` (5)
Payload: `[code str16][my_name str16]`. The **only** action of the code
holder and the only user-side confirmation required for a friend request.
- `my_name` (≤ 32, empty → `друг`) is what the inviter will see.
- A code with an address connects immediately; without one, the core waits
  for the inviter's LAN announcement / autodials.
- Connection status arrives via `PRESENCE` events (establishment is async).
  With a v2/v3 invite and no embedded route, `GET_CONTACT_STATE` starts at
  `pending` until the inviter's LAN discovery route is found; v1 routes
  remain on the legacy manual-add compatibility path.

Response: `[cid u32]`. Errors: `BAD_INVITE_CODE`, `BAD_ARGS`.

#### Extended invite and contact observation (API 2.7.0)

`CREATE_INVITE_EX` (49) takes `[mode u8][name str16][direct str16][relay str16]`
and responds `[code str16][invite_id 16]`. Modes: `0` discovery, `1` direct,
`2` relay-only, `3` direct-then-relay (versioned `stille://i3/` hybrid code; legacy `shopot://i3/` is also accepted).
Addresses are `host:port`; direct modes are rejected while Tor IP masking is
enabled. `invite_id` is random and non-secret; it cannot recover the invite key.

`CREATE_INVITE_EX` mode 4 (API 2.8.0) is the **persistent profile code**:
the secret is not random but derived deterministically from the identity
seed (HKDF), so the code never burns — every valid JOIN is accepted,
forever, and the invite registry is not involved (no `TOO_MANY_INVITES`
limit, validation is stateless). Any endpoint combination is allowed
(direct, relay, hybrid, or none); a relay endpoint is recommended for
shared profile codes because it works across networks. Repeating the call with
the same arguments returns the same code. `invite_id` for mode 4 is the
deterministic non-secret marker BLAKE2s-256(bundle)[0..16] (the
`GET_IDENTITY` fingerprint prefix); `GET_INVITE_STATE` on it always
answers active/never-expires. Security posture: the code is a capability
— anyone who obtains it can add the owner (like a public profile link);
abuse is handled with `BLOCK_CONTACT` and `REGENERATE_PROFILE_CODE` (54).
Relay presence for a mode-4 relay code is held while the daemon runs;
after a restart the GUI re-issues the same call to restore it (the code
itself is unchanged).

`REGENERATE_PROFILE_CODE` (54, API 2.8.0) takes an empty payload and
returns `[epoch u32][persisted u8]`. The profile secret is
HKDF(seed, domain‖epoch): bumping the epoch changes the secret, so a
leaked code stops passing JOIN validation immediately (only the current
epoch is accepted — no grace window). The new code is obtained by
re-issuing `CREATE_INVITE_EX` mode 4. The epoch is persisted BEFORE the
bump as an encrypted `.set`(subtype 8) log record; a failed write returns
`INTERNAL` without changing the epoch (state stays consistent with disk).
`persisted=0` means no log (run-without-storage mode): the rotation lives
only until restart. Existing contacts and sessions are unaffected — they
authenticate via the handshake, not the code. A mode-4 relay loop
re-derives the secret per cycle and picks up the new epoch by itself.

`GET_INVITE_STATE` (50) takes `[invite_id 16]` and returns
`[state u8][accepted_cid u32][expires_at_ms i64]`. States: 0 active, 1 joining,
2 consumed, 3 expired (reserved), 4 failed. `joining` means a valid JOIN was
received and bind is in progress; `consumed` is recorded after bind. Neither
state is a request for another user confirmation.

`ACCEPT_INVITE_EX` (44) has the same request payload as `ACCEPT_INVITE` and
responds `[cid u32][disposition u8][state u8][attempt u32]`. Dispositions:
0 accepted, 1 already pending, 2 already connected. It schedules dialing and
returns immediately; it does not claim cryptographic trust before JOIN.

`GET_CONTACT_STATE` (43) takes `[cid u32]` and returns
`[state u8][attempt u32][last_error u16][next_retry_ms u32]`. `ConnState`:
0 pending, 1 discovering, 2 dialing, 3 handshaking, 4 joining, 5 online,
6 offline, 7 failed. `ConnErr` values 0–9 are none, discovery disabled,
transport unavailable, transport timeout, auth failed, join timeout, capacity
exhausted, relay unreachable, Tor unavailable, canceled. Auth failure details
are intentionally not exposed.

`SUBSCRIBE_CONTACT_UPDATES` (45) takes an empty payload, returns
`[epoch 16][revision u64]`, and enables events 15–17 on that API connection.
`GET_BOOTSTRAP` (46) returns `[version 3×u16][epoch 16][revision u64]
[count u32] × {contact_view}`. `GET_CONTACTS_DELTA` (47) takes
`[epoch 16][from_revision u64]`; it returns revisioned contact changes or
`RESYNC_REQUIRED` when the epoch/window is stale. `GET_REACHABLE_ENDPOINTS` (48)
takes an empty payload and returns `[count u8] × [address str16]` local IPv4
`host:port` candidates (not a reachability guarantee). `GET_HISTORY_PAGE` (51)
takes `[cid u32][has_cursor u8][before_ts u64][before_msg_id 16][limit u16]`
and returns `[has_more u8][next_ts u64][next_msg_id 16][count u32] × history
entry`, newest to oldest. The next cursor is exclusive; limit 0 defaults to 30,
maximum 200. `next_*` identifies the oldest entry in the returned page and is
zeroed when there is no page.

#### Short identity codes (API 2.8.0)

`GENERATE_SHORT_CODE` (52) takes `[cid u32 (0 = my identity)]` and returns
`[cid u32][code str16]`. The code is 9 Crockford-base32 characters
(ambiguous I/L/O/U excluded): 8 data characters carrying the first 40 bits
of SHA-256(bundle) plus 1 positional checksum character. It is fully
deterministic — the same bundle always yields the same code — and requires
no storage. The code is an **identifier, not a secret**: it grants no
rights, does not reveal the bundle, and anyone who knows the public bundle
can compute it. `DECODE_SHORT_CODE` normalizes input case and common
Crockford typos (I/l→1, O→0, U→V).

`DECODE_SHORT_CODE` (53) takes `[code str16]` and returns
`[cid u32 (0 = my identity)][full_code str16]`, or `NOT_FOUND`. The full
code is the v1 format (`shopot1.<base64url(bundle|name)>`, with `@host:port`
when the contact has a last known address). The 9-character code is
information-theoretically irreversible (45 bits < the 512-bit bundle):
resolution works only for bundles the core already knows — the local
identity and stored contacts. `stille.im` invite links therefore carry the
full code itself, with the `stille://` scheme stripped
(`stille.im/invite/i/…`, `stille.im/invite/i3/…`): the site is a redirector
only and holds no mapping; the client re-attaches the scheme and feeds the
code to `ACCEPT_INVITE`/`ACCEPT_INVITE_EX` directly. Short codes remain a
local identifier for known contacts, not a link payload.
Blocked contacts resolve normally (blocking is a rendering decision).
A 40-bit hash collision between two contacts resolves deterministically to
the lower cid. Errors: `BAD_ARGS` (malformed code), `NO_CONTACT` (unknown
cid in generate), `BAD_FRAME`.

#### `LIST_CONTACTS` (6)
Payload: ∅. Response:
```
[count u32]
× { [cid u32][flags u8 (bit0 online, bit1 blocked)][last_seen_ms i64 (0 = unknown)][name str16] }
```

### 4.3 Messages

#### Formatting entities (v2)

Every message payload in this section (request, response, event) carries an
**entity tail** after the body — the same canonical encoding as the TEXT
envelope on the wire (PROTOCOL.md §7.1):

```
[ent_count u8 ≤ 32]
× { [kind u8][offset u16][len u16][value_len u8][value bytes] }
```

| kind | Meaning | value |
|---|---|---|
| 1 | bold | — |
| 2 | italic | — |
| 3 | underline | — |
| 4 | strikethrough | — |
| 5 | spoiler | — |
| 6 | code (inline) | — |
| 7 | code block | language tag, optional |
| 8 | link | URL, mandatory, ≤ 255 bytes |

- `offset`/`len` are **UTF-8 byte** offsets into the body. The core does not
  validate UTF-8; slicing on character boundaries at render time is the
  client's job.
- Rules enforced by the core: `len ≥ 1`, `offset + len ≤ body_len`, entries
  sorted by offset, value presence per kind; overlaps allowed
  (bold + italic on the same span). Violations → `BAD_ARGS`
  (semantics) or `BAD_FRAME` (truncated structure).
- The count byte is always present; 0 formatting → a single `0x00` byte.

#### `SEND_MESSAGE` (7)
Payload: `[cid u32][body str16 ≤ 4096][entity tail]`.
Response: `[msg_id 16][flags u8 (bit0 = queued)]`.
- Sending to an offline contact is NOT an error: `queued=1` — the message
  leaves when the contact appears (outbox; confirmation is the
  `MESSAGE_DELIVERED` event).
- Errors: `NO_CONTACT`, `CONTACT_BLOCKED`, `BAD_ARGS` (empty body, invalid
  entities).

#### `SEND_REPLY_MESSAGE` (33)
Payload: `[cid u32][reply_to_msg_hex str16][body str16 ≤ 4096][entity tail]`.
`reply_to_msg_hex` is exactly 32 ASCII hexadecimal characters (the lowercase
form returned by clients when rendering `msg_id`). The referenced message must
exist in the same chat; otherwise `NOT_FOUND`. Response matches `SEND_MESSAGE`:
`[msg_id 16][flags u8 (bit0 = queued)]`. Replies use a separate authenticated
`REPLY_TEXT` transport envelope and survive history/outbox restart.

#### `SET_REACTION` (8) / `REMOVE_REACTION` (9)
Payload: `[cid u32][msg_id 16][codepoint u32]`.
- The codepoint is a Unicode code point, U+0000..U+10FFFF; outside the range
  → `UNSUPPORTED_REACTION`. A reaction requires a live session.
- At most three active reaction codepoints are retained per message. Duplicate
  adds update their timestamp; adding a fourth while three are active is ignored
  by retrieval but remains a valid wire operation.
- Response: ∅. Errors: `NO_CONTACT`, `NO_SESSION`, `UNSUPPORTED_REACTION`,
  `CONTACT_BLOCKED`.

#### `GET_REACTIONS` (34)
Payload: `[msg_id 16]`. Response: `[react_count u32] × {[flags u8 bit0 mine][codepoint u32][ts_ms u64]}`;
removals are resolved and the count is capped at 3. `GET_MESSAGE` returns the
same resolved reaction view.

#### `GET_HISTORY` (10)
Payload: `[cid u32][limit u32]` (0 → 50; maximum 200 → `TOO_BIG`).
Response:
```
[total u32]   — total records for the contact
[count u32]
× { [flags u8 (bit0 mine, bit1 delivered)][msg_id 16][ts_ms u64][body str16][entity tail] }
```
Records oldest → newest. `ts_ms` is local record time (ms, epoch). Stored in
the encrypted log, survives restarts. No log → empty list
(`total=0, count=0`). The window is cut by `limit` **and** the 16 MiB payload
budget: with entity-heavy history `count` may be smaller than `limit`.

#### `GET_MESSAGE` (11)
Payload: `[msg_id 16]`. Response:
```
[cid u32][flags u8 (bit0 mine, bit1 delivered)][ts_ms u64][body str16][entity tail]
[react_count u32]
× { [flags u8 (bit0 mine)][codepoint u32][ts_ms u64] }
```
No record → `NOT_FOUND`. `bit1 delivered` is set by the receiver's ACK
(`MESSAGE_DELIVERED`), not by the fact of writing to the socket: a sent
message shows `delivered=0` until the ACK arrives. History is served from
an in-memory cache; the log is read once at daemon start.

#### `SEARCH_MESSAGE` (23) / `GLOBAL_SEARCH_MESSAGE` (24)
Payload: `[cid u32][query str16][limit u32][offset u32]` (global: without
`cid`). Response: `[total u32][count u32] × {[cid u32] (global only)
[flags u8 (bit0 mine, bit1 delivered, bit2 fuzzy)][msg_id 16][ts_ms u64]
[body str16][entity tail]}`. Case-insensitive exact substring matches
first (newest → oldest), then fuzzy (word-level Levenshtein) for a
single-word query. Errors: `BAD_ARGS` (empty query), `TOO_BIG`.

### 4.4 Own profile

#### `SET_NAME` (12)
Payload: `[name str16 1..32]`. Response: ∅. Sent to peers in PROFILE (online
— immediately; offline — at the next session).

#### `SET_AVATAR` (13)
Payload: `[data str32 1..16000]` — image bytes inline (format is not parsed
by the core). Response: `[avatar_id 16][size u32]`.
- `avatar_id = SHA-256(data)[0..16]` — content addressing.
- Storage: encrypted log, survives restarts.

#### `GET_MY_AVATAR` (40, since API 2.5.0)
Payload: ∅. Response: `[avatar_id 16][data str16 1..16000]`.
Returns the current own avatar from the encrypted-log-backed cache, including
with a fresh client after restarting the daemon. No peer connection is needed.
Errors: `NOT_FOUND` if no own avatar is set or its bytes are unavailable;
`BAD_FRAME` for a nonempty payload. Clients should call this once on connect
to restore their own preview, and use the uploaded bytes after `SET_AVATAR`.
No plaintext image file is created. Existing methods, peer wire format and
storage format are unchanged; older cores return `UNKNOWN_METHOD` (check
`GET_VERSION`).

#### `GET_AVATAR_ID` (14)
Payload: `[cid u32]`. Response: `[avatar_id 16]` (all zeros — no avatar).
The bytes themselves arrive as the `AVATAR_RECEIVED` event: the core requests
them itself (AVATAR_REQ) on an id mismatch and self-heals on reconnect — the
client only listens for the event and caches by id.

### 4.5 Files

#### `SEND_FILE` (15)
Payload: `[cid u32][path str16]` — a path in the daemon user's filesystem
(the client drops the file, e.g., into `$HOME/.stille-messenger/tmp/`, and passes the
path).
- Limit 64 MB. Without a live session the transfer is queued (outbox
  semantics) and flushed when a session appears.
- The name is taken from the path (basename, ≤ 64 bytes).

Response: `[file_id 16][size u32][chunks u32]`.
- `file_id = SHA-256(file)[0..16]`; the receiver verifies the hash and stores
  the file at `~/.stille-messenger/files/<hex>` (0600). A duplicate is not re-sent.
- The receiver gets the `FILE_RECEIVED` event; the sender gets `FILE_SENT`
  when all chunks are acknowledged.
- Errors: `NO_CONTACT`, `FILE_NOT_FOUND`, `TOO_BIG`, `BAD_ARGS`.

### 4.6 Calls

| Method | id | Payload | Response |
|---|---|---|---|
| `START_CALL` | 16 | `[cid u32]` | `[call_id 16]` |
| `ANSWER_CALL` | 17 | ∅ | ∅ |
| `END_CALL` | 18 | ∅ | ∅ |

- Voice: 16 kHz mono, E2EE, IMA-ADPCM 4:1, DTX (see PROTOCOL.md §10).
- One line per daemon: `START_CALL` during an active call → `BUSY`;
  `ANSWER/END` without a call → `NO_CALL`. `START_CALL` without a session →
  `NO_SESSION`.
- Audio flows through the FIFOs `~/.stille-messenger/pcm/mic` and `~/.stille-messenger/pcm/spk`
  (the core reads/writes).
- State changes arrive as `CALL_STATE` events.

### 4.7 Blocking and transport

| Method | id | Payload | Response |
|---|---|---|---|
| `BLOCK_CONTACT` | 19 | `[cid u32]` | ∅ |
| `UNBLOCK_CONTACT` | 20 | `[cid u32]` | ∅ |
| `CONNECT` | 21 | `[cid u32][addr str16]` | ∅ |
| `LISTEN` | 22 | `[addr str16][cid u32]` | ∅ |

`BLOCK_CONTACT`: traffic is dropped, the peer is notified. `CONNECT`/`LISTEN`
are normally unnecessary (autodial/LAN handle it); errors — `NO_CONTACT`,
`TRANSPORT_FAILED`, `NO_RELAY`.

### 4.8 Chats: pinning, deletion, contact cards

| Method | id | Payload | Response |
|---|---|---|---|
| `PIN_CHAT` | 25 | `[cid u32]` | ∅ |
| `GET_PINNED_CHAT` | 26 | ∅ | `[cid u32]` (0 = none) |
| `UNPIN_CHAT` | 27 | ∅ | ∅ |
| `DELETE_CHAT` | 28 | `[cid u32]` | ∅ |
| `SEND_CONTACT` | 29 | `[to_cid u32][contact_cid u32]` | ∅ |
| `PIN_MESSAGE` | 30 | `[cid u32][msg_id 16]` | ∅ |
| `UNPIN_MESSAGE` | 31 | `[cid u32][msg_id 16]` | ∅ |
| `GET_PINNED_MESSAGES` | 32 | `[cid u32]` | `[count u32] × {[msg_id 16]}` |
| `SEND_REPLY_MESSAGE` | 33 | `[cid u32][reply_to_msg_hex str16][body str16][entity tail]` | `[msg_id 16][flags u8]` |
| `GET_REACTIONS` | 34 | `[msg_id 16]` | `[count u32] × {[flags u8][codepoint u32][ts_ms u64]}` |

- One pinned chat per daemon (idempotent re-pin). Pins survive restarts
  (encrypted log).
- `DELETE_CHAT` removes the conversation and the contact: the session is
  torn down, outbox/file queues/history/reactions/pins of the chat are
  purged. Re-meeting the same person (a new invite from them) creates a
  **new cid with a clean history**. Until a restart the slot stays reserved
  (cids of other chats do not shift); after a restart deleted slots are not
  re-created — `LIST_CONTACTS` may return renumbered cids, so a client
  re-syncs at bootstrap anyway.
- `SEND_CONTACT` forwards a contact card (name, bundle, and — if known —
  address) over a live session; `contact_cid = 0` sends your own card. The
  receiver gets the `CONTACT_CARD` event. A card introduces, it does not
  connect: adding that person requires their own invite. Errors:
  `NO_CONTACT`, `CONTACT_BLOCKED`, `NO_SESSION`.
- `PIN_MESSAGE` requires the message to exist in that chat's history
  (`NOT_FOUND`); ≤ 16 pinned messages per chat (`TOO_BIG`). The order of
  `GET_PINNED_MESSAGES` is the pinning order. `UNPIN_MESSAGE` is idempotent.

### 4.9 Configuration and the client database

| Method | id | Payload | Response |
|---|---|---|---|
| `GET_CONFIG` | 35 | ∅ | config blob (below) |
| `SET_CONFIG` | 36 | config blob | ∅ |
| `WRITE_DB` | 37 | `[tag u8][data str32 ≤ 65000]` | `[rec_id u32][ts_ms u64]` |
| `READ_DB` | 38 | `[tag u8 (0xFF = any)][limit u32 (0 → 50, ≤ 200)][offset u32]` | `[total u32][count u32] × {[rec_id u32][ts_ms u64][tag u8][data str16]}` |
| `DELETE_DB` | 39 | `[rec_id u32]` | ∅ |

#### Configuration blob

The configuration is one binary blob, persisted in the encrypted log
(kind `cfg`, last record wins; a fresh daemon starts with defaults):

```
[ver u8 = 1][flags u32 LE][server_addr str16][tor_addr str16]
```

`flags` bits (unknown bits in `SET_CONFIG` are rejected with `BAD_ARGS`):
bit0 `server_mode`, bit1 `use_fake_tls`, bit2 `use_tor_mask`, bit3
`device_sync`, bit4 `lan_discovery`, bit5 `autodial`, bit6 `nat_punch`.
Addresses are `host:port` (≤ 64 bytes; empty = unset). Defaults: all
flags on except `server_mode` and `use_tor_mask`; `tor_addr` =
`127.0.0.1:9050`.

- `server_mode` — all peer traffic flows through the user's **own**
  self-hosted relay (`server_addr`, `stille-messenger-core relay`). Requires `server_addr`
  (`BAD_ARGS` otherwise). Presence threads dial every contact through it.
- `use_fake_tls` — wrap direct transports as fake-TLS. **Both peers must
  match**: a mismatched peer fails the handshake (existing sessions are
  unaffected; new dials follow the flag).
- `use_tor_mask` — direct dials go through the Tor SOCKS5 proxy
  (`tor_addr`). Relay connections do not use Tor (the relay already hides
  the IP). Requires `tor_addr` (`BAD_ARGS`); a dead proxy →
  `TOR_UNAVAILABLE` from `CONNECT`.
- `device_sync` — replicate the database to a linked device (below).
- `lan_discovery` — UDP multicast announcements/search in the LAN.
- `autodial` — background redialing of offline contacts by saved address.
- `nat_punch` (2.9.0) — upgrade relayed sessions to a direct punched
  connection: the core exchanges direct-path candidates inside the
  authenticated session and runs a simultaneous TCP open from the same
  local port as the relay connection (PROTOCOL.md §15.1). Works only
  between relayed peers (relay address from the invite / contact memory /
  `server_mode`); failure (symmetric NAT, filter) is silent — the pair
  stays on the relay. The route change is reported as `ROUTE_STATE` (§5).

`SET_CONFIG` validates and applies atomically, persists, broadcasts
`CONFIG_CHANGED` (payload = the new blob), and — with `device_sync` on —
replicates the blob to the linked device (see below). Errors: `BAD_FRAME`
(structure/version), `BAD_ARGS` (unknown flag bits, `server_mode`/
`use_tor_mask` without an address, malformed addresses), `INTERNAL`.

#### Client database (`WRITE_DB`/`READ_DB`/`DELETE_DB`)

The client's own data (drafts, layout, settings, caches — anything the
UI wants to survive restarts) lives **inside the encrypted log** under a
tag namespace owned by the client. Records carry a core timestamp and are
returned oldest-first. `tag = 0xFF` is the read wildcard (rejected by
`WRITE_DB` with `BAD_ARGS`); `rec_id` is the log record number returned by
`WRITE_DB` and accepted by the idempotent `DELETE_DB` (a log tombstone;
storage is reclaimed at compaction).

Limits: one record's data ≤ 65000 bytes (`TOO_BIG`); the live client area
is capped at 16 MiB total (`TOO_BIG`); `READ_DB` limit 0 → 50, ≤ 200.

#### Device sync (`device_sync`)

A *device link* is a contact whose bundle equals your own: two installs
that share the same identity seed (e.g. a phone and a laptop), paired with
a regular invite code (`ACCEPT_INVITE` — exactly one link per bundle:
`TOO_BIG` for a second). On the invite holder, LAN discovery of the same
bundle updates the stored route and continues into the authenticated dial path;
the holder role initiates while the inviter's waiter role accepts. With `device_sync` on, the core replicates
records (messages, reactions, acks, contacts, blocks, files, config, and
client-DB records up to the sync record size) to the linked device over
the session, in bounded queues with retry semantics like the outbox;
duplicates are dropped by record MACs/ids. Client-DB records replicate
with their data; **deletion does not** (`DELETE_DB` is local — a client
protocol may express deletions as its own records). Avatars and pinned
state are not synced in v1. The link itself: the invite holder always
initiates, so exactly one side redials.

### 4.10 Account recovery (since API 2.6.0)

Recovery restores **access, not history**. A fresh install of the daemon
without `~/.stille-messenger/zig-seed` starts in **unprovisioned serve mode**: an
ephemeral random identity (never persisted, never on the network), no log,
no networking threads — the UDS API is up and waits for the client to
either create a profile (CLI `init`, then restart serve) or restore one.

The backup is a sealed blob the client stores in the **user's own cloud**
(reference: Google Drive `appDataFolder`, see
[CLIENT_RULES.md](../../CLIENT_RULES.md) §4). The client supplies a
32-byte **unlock secret** (WebAuthn PRF output or a recovery code); the
core derives the AEAD key (HKDF-SHA256) and seals/opens the blob. The
core never persists or logs the secret.

Contents (what survives recovery): identity seed, profile name, avatar
bytes, core config, contacts with routes (direct address, personal relay
address, device-link role), block list. **Not included:** message
history, files, pins, client-DB records. After restore the peer devices
see the same identity (same bundle) and keep writing to the same chats.

#### `CREATE_RECOVERY_BACKUP` (41)
Request `[unlock_secret 32]` → response `[backup str32]`.
Requires a provisioned profile (`NOT_INITIALIZED` otherwise; the seed is
re-read from disk — if the file is gone, the package cannot include it).
The blob is opaque to the client. `TOO_BIG` if the profile exceeds the
package caps (§6).

#### `RESTORE_RECOVERY_BACKUP` (42)
Request `[backup str32][unlock_secret 32]` → response
`[bundle 64][fingerprint 32][name str16]`. Empty blob → `BAD_ARGS`.
Applies only to an empty profile: on a live profile or when a seed file
appears on disk behind the daemon's back → `ALREADY_PROVISIONED` (never
silently overwrites). Wrong secret / corrupt blob / unknown format →
`BAD_RECOVERY`.

Apply order (client-visible effect): all profile records are written to a
fresh encrypted log, **then** the seed is saved (commit point) — a failure
before that leaves the profile empty and the retry clean (a half-written
log is discarded, no duplicate contacts). After success the identity is
swapped in place, the profile reloads, and the daemon brings networking up
by itself.

## 5. Events (EVENT)

Broadcast to all connected clients, in any order, `request_id = 0`.

| Name | id | Payload |
|---|---|---|
| `MESSAGE_RECEIVED` | 1 | `[cid u32][msg_id 16][ts_ms u64][name str16][body str16][entity tail]` |
| `MESSAGE_DELIVERED` | 2 | `[cid u32][msg_id 16]` |
| `PRESENCE` | 3 | `[cid u32][online u8 (1/0)][last_seen_ms i64]` |
| `REACTION` | 4 | `[cid u32][msg_id 16][op u8 (1 = add, 2 = remove)][codepoint u32][ts_ms u64]` |
| `CALL_STATE` | 5 | `[cid u32][call_id 16][state u8 (1 offer, 2 accept, 3 reject, 4 end)]` |
| `AVATAR_RECEIVED` | 6 | `[cid u32][avatar_id 16][data str16 ≤ 16000]` |
| `FILE_RECEIVED` | 7 | `[cid u32][file_id 16][size u32][name str16]` |
| `CONTACT_JOINED` | 8 | `[cid u32][name str16]` |
| `CONTACT_PROFILE` | 9 | `[cid u32][name str16][avatar_id 16]` |
| `BLOCKED_BY_PEER` | 10 | `[cid u32]` |
| `FILE_SENT` | 11 | `[cid u32][file_id 16][size u32][name str16]` |
| `CONTACT_CARD` | 12 | `[cid u32][name str16][bundle 64][addr str16]` |
| `REPLY_RECEIVED` | 13 | `[cid u32][msg_id 16][reply_to 16][ts_ms u64][name str16][body str16][entity tail]` |
| `CONFIG_CHANGED` | 14 | config blob (§4.9: `[ver u8][flags u32][server_addr str16][tor_addr str16]`) |
| `ROUTE_STATE` | 18 (2.9.0) | `[cid u32][route u8]`: 0 lan (direct dial by host candidate), 1 relay, 2 direct-punched (NAT-punch succeeded) — subscription required, like 15–17 |

The connection-observation events are opt-in: call `SUBSCRIBE_CONTACT_UPDATES`
before expecting events 15–18. `CONTACT_STATE_CHANGED` is a transport/UI
state notification; `CONTACT_UPSERTED`/`CONTACTS_CHANGED` carry revisioned
snapshot changes. They do not replace authenticated JOIN or `CONTACT_JOINED`.
`ROUTE_STATE` (2.9.0) fires when a relay session is replaced by a direct
punched/LAN connection (and once with route=1 when a relay session binds):
a relay **downgrade** never happens, so route=1 after 2 means a new relay
session after the direct path died.

- `MESSAGE_RECEIVED.ts_ms` = local receive time, consistent with GET_HISTORY
  timestamps. The `msg_id` is what reactions address.
- `PRESENCE`: render the online status from this event only — do not poll.
- `CALL_STATE`: reject/end always terminate the audio loop (after reject, an
  end follows too).
- `CONTACT_JOINED`: the holder of your invite has connected — the contact
  exists now.
- `CONTACT_PROFILE`: the contact's name/avatar_id changed (PROFILE echo).
- `CONTACT_CARD`: a peer forwarded a third party's contact card
  (SEND_CONTACT). The cid is the sender's; `addr` is empty when unknown.
  A card introduces, it does not connect — adding the person requires
  their own invite.
- `CONFIG_CHANGED`: the configuration changed — locally (`SET_CONFIG`)
  or applied from a linked device (device sync). The payload is the new
  blob (§4.9); re-read state that depends on the flags.

## 6. Limits (canonical table)

| Limit | Value |
|---|---|
| frame payload | 16 MiB |
| text body | 4096 bytes |
| display name | 32 bytes |
| avatar payload | 16000 bytes (one wire frame); receive rate ≤ 1 per 5 min |
| file size | 64 MB |
| file chunk | 16000 bytes |
| concurrent file transfers per peer | 8 |
| history limit parameter | 200 (0 → default 50) |
| search limit parameter | 200 (0 → default 50) |
| search query | 4096 bytes (case-insensitive: simple fold of ASCII + Cyrillic, other scripts as-is) |
| outbox | 1000 records, TTL 30 days |
| live invites | 4 (daemon memory, not persisted) |
| message dedup window | 64 msg_ids per contact |
| pinned chats | 1 per daemon |
| pinned messages | 16 per chat |
| config address fields | 64 bytes each (`host:port`) |
| client DB: one record's data | 65000 bytes |
| client DB: live area total | 16 MiB |
| recovery package | ≤ 92786 bytes (§4.10) |
| recovery: contacts / blocks | 256 / 256 |
| device sync queue | 512 records / 2 MiB per device; batch ≤ 64 records / 16000 bytes; one record ≤ 4034 bytes |
| contact card name / address | 32 / 64 bytes |
| presence | PING after 4 s idle; 5 s interval; 3 misses → offline |
| direct TCP port range | 7777–7786 (first free wins; all busy → LAN discovery off) |
| LAN discovery | UDP multicast 239.77.77.77:57770 + limited broadcast, 74-byte announcements; cadence 500 ms (100 ms burst while an outbox entry or JOIN is pending), immediate announce on a send to an offline peer; unicast reply on hearing a peer |
| direct dial deadline | 3000 ms on every direct dial (relay-marker pairing and Tor SOCKS5 paths excluded) |
| NAT punch (2.9.0) | ≤ 4 reflexive candidates per frame side, ≤ 8 candidates total; 3 rounds × 500 ms per attempt (50 ms retry slices), 5 s between attempts; 1 punch worker per contact; punch candidates only inside an authenticated session |
| daemons per `$HOME` | 1 (single UDS path) |

## 7. Delivery model

1. `SEND_MESSAGE` to an offline peer → response `queued=1`. The GUI shows
   "will send later". The same call triggers the connect path immediately:
   a dial job to the last known address (if any) plus a burst discovery
   announcement in parallel (the address may be stale; address unknown —
   discovery only) — delivery does not wait for background cycles.
2. The peer appears (LAN/autodial) → the core flushes the queue itself.
3. The receiver of every TEXT sends an ACK envelope → the sender gets
   `MESSAGE_DELIVERED`: the GUI shows the "delivered" check. This ACK —
   and only this ACK — sets the `delivered` bit in `GET_HISTORY`/
   `GET_MESSAGE`/search records (including after a restart); an offline
   queue entry is not a delivery.
4. Duplicates are impossible: msg_ids are deduplicated on receipt.
5. The queue survives a daemon restart (encrypted log); limits: 1000
   records, TTL 30 days.

Presence: online = live connection; silence > 4 s → PING/PONG; 3 misses →
offline (`PRESENCE` with online=0).

## 8. Client lifecycle

Bootstrap (analog of a gateway READY):

```
connect to $HOME/.stille-messenger/api.sock
GET_VERSION                       — readiness probe, check major
GET_IDENTITY                      — OK → proceed; NOT_INITIALIZED → onboarding (§4.10)
LIST_CONTACTS                     — full contact snapshot
for each cid: GET_HISTORY(cid,50) — initial history
render; from here on, state arrives via events only
```

After bootstrap the client is purely event-driven: presence, messages,
reactions, calls, avatars, files all arrive as events. Do not poll.

`NOT_INITIALIZED` from `GET_IDENTITY` means the daemon is unprovisioned
(no seed file at start, §4.10): the client shows onboarding — create a
new profile (CLI `init` + serve restart) or restore one
(`RESTORE_RECOVERY_BACKUP`). Identity-methods on the ephemeral identity
are refused (`GET_IDENTITY`/`CREATE_RECOVERY_BACKUP`); transport methods
fail naturally (`NO_CONTACT`/`NO_SESSION`).

## 9. Scenarios (in API terms)

### Adding a friend (same Wi-Fi)
```
A: CREATE_INVITE{name:"mom"}             → one friend-request key
   (relay the key through any messenger)
B: ACCEPT_INVITE{code, my_name:"mom"}    → cid
   then: the session comes up by itself, PRESENCE online, text flows
A: receives CONTACT_JOINED; no second key or manual confirmation is needed
```

### Remote (both behind NAT, relay)
```
A: runs stille-messenger-core relay host:port on any server
A: CREATE_INVITE{relay=1}                  → code stille://i/…@r/host:port
B: ACCEPT_INVITE{code}                     → cid; session over the relay
both: ROUTE_STATE{cid, route=1 relay}      (subscribed clients)
then: punch — ROUTE_STATE{cid, route=2 direct-punched}, session is direct
      (symmetric NAT / port-restricted filter: stays relay=1 silently)
```
No third-party STUN; the relay is the rendezvous point (PROTOCOL.md §15.1).

### Remote (behind NAT, address known)
A: `CREATE_INVITE{name, addr:"host:7777"}` → B: `ACCEPT_INVITE`.
IP hiding: A runs `stille-messenger-core relay host:port` anywhere and issues
`CREATE_INVITE` with relay=1.

### Offline conversation
A writes to offline B → `queued=1` → B starts the daemon → the core delivers
→ A: `MESSAGE_DELIVERED`.

### Second device (phone + laptop)
```
both:   one identity — copy ~/.stille-messenger/zig-seed between installs (out of band)
phone:  CREATE_INVITE{}                        → code
laptop: ACCEPT_INVITE{code}                    → cid (device link)
both:   SET_CONFIG{device_sync=1}              → history/client DB replicate
        records flow while the session is up; the link redials by itself
```

### Account recovery (new device, no seed)
```
fresh:  stille-messenger-core serve                  — unprovisioned (no seed file)
client: GET_IDENTITY                            → NOT_INITIALIZED
client: downloads the blob + PRF salt from the user's cloud
client: RESTORE_RECOVERY_BACKUP{blob, unlock_secret}
        → [bundle 64][fingerprint 32][name str16]; networking comes up
client: CREATE_RECOVERY_BACKUP{unlock_secret}   → fresh blob → upload
        (after profile changes; see CLIENT_RULES.md §4.3)
```

## 10. Guarantees and boundaries

- Cryptography: XX-like handshake, AEAD transport, double ratchet — see
  PROTOCOL.md. The client never touches keys: the seed lives at
  `~/.stille-messenger/zig-seed` (0600).
- Concurrent clients: commands execute sequentially; events are broadcast to
  all.
- Permissions: `~/.stille-messenger` — 0700, `api.sock` — 0700, `zig-seed` — 0600.
  Everything is local to one OS user.
- Call jitter buffer: frames play from a queue at an even pace (~40–60 ms
  latency); losses are concealed by skipping seq.
- The wire is disguised as TLS 1.3 (fake-TLS) by default; `use_fake_tls`
  disables the disguise (both peers must match). The peer sees your IP
  (P2P); hiding it requires a relay or Tor (`use_tor_mask`).
- Socket and files belong to `$HOME`; running several daemons on one `$HOME`
  is unsupported (single UDS path).

## 11. Versioning policy

- `GET_VERSION` returns `[major, minor, patch]`.
- **Major** — incompatible wire changes of this contract; a client must
  check it and refuse to work against a different major.
- **Minor** — compatible additions (new methods, events, payload fields at
  the end of a struct).
- Every change to this contract lands in [CHANGELOG.md](../CHANGELOG.md)
  before the release.

## Appendix A. Envelope quick reference

Full byte layouts — PROTOCOL.md §7. The client never constructs envelopes;
the core does. Useful for reading logs and events:

TEXT (0x10) carries msg_id/ts/body + the formatting entity tail; ACK (0x15) —
delivery confirmation;
REACT (0x13) — op + codepoint; JOIN (0x40) — invite proof; PROFILE (0x42) —
name + avatar_id; CONTACT_CARD (0x43) — a forwarded third-party contact card;
AVATAR/AVATAR_ACK/AVATAR_REQ (0x50/0x51/0x52) — avatars;
FILE_META/FILE_DATA/FILE_ACK (0x60/0x61/0x62) — files;
CALL_SIGNAL/CALL_AUDIO (0x30/0x31) — calls; PING/PONG (0x20/0x21) — presence;
BLOCK_NOTICE (0x14) — blocking.
