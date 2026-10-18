# CLIENT_RULES.md — binding contract for stille-messenger GUI clients

This document is **normative for every GUI client** of stille-messenger
(desktop, mobile, web-companion). Anything marked MUST is required for a
client to be considered a valid stille-messenger front-end; SHOULD means
strongly recommended. The core's wire contract is
[`core/docs/CORE-API.md`](core/docs/CORE-API.md) (API 2.6.0); this file
translates it into client-side requirements and flows.

The Russian mirror of this document is
[`docs/ru/CLIENT_RULES.md`](docs/ru/CLIENT_RULES.md).

---

## 1. Connection basics (MUST for all clients)

- Connect to the core over the Unix domain socket `$HOME/.stille-messenger/api.sock`
  (0700, same user). No TCP, no HTTP.
- Wire protocol is **binary, little-endian, fixed-width** (no JSON, no
  varint). Every frame is a 16-byte header + payload:

  ```
  [0..2]   magic "ZP" (0x5A50 LE)
  [2]      version = 1
  [3]      kind: 1 request, 2 response, 3 event
  [4..6]   method (request/response) or event id (event), u16 LE
  [6..10]  request_id u32 LE (client-chosen, echoed in response; 0 for events)
  [10..12] status u16 LE (responses only)
  [12..16] payload_len u32 LE (max 16 MiB)
  [16..]   payload
  ```

- Strings on the wire are length-prefixed raw bytes: `str16` = `[len u16][bytes]`,
  `str32` = `[len u32][bytes]`. Empty string is `len = 0`, no bytes.
- Send `GET_VERSION` first and **refuse to operate on major mismatch**.
  Minor/patch: warn. Current version: `2.6.0`.
- Use one request per `request_id` and match responses by it; a response
  may arrive in any order relative to other requests.

## 2. Bootstrap and event-driven operation (MUST)

- Bootstrap sequence on connect:
  1. `GET_VERSION` — capability handshake.
  2. `GET_IDENTITY` — own bundle + fingerprint.
     - Status `NOT_INITIALIZED` (19): the core has **no profile** (daemon
       started in recovery mode). Go to §5 onboarding.
  3. `LIST_CONTACTS`, then `GET_HISTORY` per open chat on demand.
- **No busy-polling.** State updates arrive as event frames (kind 3);
  the client MUST maintain the connection and handle, at minimum:
  `MESSAGE_RECEIVED`, `MESSAGE_DELIVERED`, `PRESENCE`, `REACTION`,
  `CONTACT_JOINED`, `CONTACT_PROFILE`, `FILE_RECEIVED`, `FILE_SENT`,
  `CALL_STATE`, `CONFIG_CHANGED`. Reconnect + re-bootstrap on socket loss.
- History is pulled once per chat (`GET_HISTORY`), then maintained from
  events. Do not refetch full history on every focus.

## 3. Onboarding: three start paths (MUST support all three)

A fresh device is in exactly one of these states:

1. **Existing local profile** — `GET_IDENTITY` returns OK. Show chats.
2. **New account** — user wants a brand-new identity:
   the client MUST create the profile via the core CLI:
   `stille-messenger-core init` (writes `~/.stille-messenger/zig-seed`, 0600), then start
   `stille-messenger-core serve`. A daemon already running in recovery mode
   cannot be provisioned by `init`; restart it after `init`.
3. **Account recovery** — user restores an existing identity from the
   recovery backup. This is the flow in §4.

> Note: `init` is the only way to create a new identity; the API has no
> "create identity" method by design (identity creation is a local,
> one-time, deliberate action, not a remote operation).

## 4. Account recovery (MUST)

The core supports **recovery without history**: a new device restores the
identity seed, profile, contacts, routes, blocks and config from an
encrypted backup blob. Message history and files are NOT part of the
backup: after restore the device starts with an empty history, but peers
see the same identity (same bundle) and keep writing to the same chats.

### 4.1 The secret and the blob

- The blob is sealed by the core with ChaCha20-Poly1305; the key is derived
  (HKDF-SHA256) from a 32-byte **unlock secret** supplied by the client.
  The core never stores this secret.
- The client MUST obtain the unlock secret one of two ways:
  1. **Passkey with WebAuthn PRF extension** (preferred). At enrollment
     (see §4.2) the client generated a random 32-byte **PRF salt** and
     saved it with the blob metadata. At unlock, evaluate the PRF with
     that salt; the 32-byte result IS the unlock secret.
  2. **Recovery code** (fallback, MUST be offered). A random 32-byte code
     generated at enrollment, shown to the user exactly once as grouped
     base32/hex, and never stored by the client. The user types it in
     when the passkey is unavailable (different platform, lost device).
- The blob and the PRF salt live in the **user's own cloud storage**.
  Reference backend: Google Drive, OAuth scope
  `https://www.googleapis.com/auth/drive.appdata` (the hidden,
  per-application `appDataFolder` — no visible files, app-scoped quota).
  Other user-controlled storage with the same properties is acceptable.
  Client MUST NOT use a project-operated server for backups.

### 4.2 Enrollment (first setup, after profile creation)

1. Generate a random 32-byte PRF salt; create a WebAuthn passkey with the
   `prf` capability:

   ```js
   const credential = await navigator.credentials.create({
     publicKey: {
       // rp, user, pubKeyCredParams, challenge as usual (ES256/EdDSA)
       extensions: { prf: {} },          // request PRF support
     },
   });
   ```

   If the authenticator does not support PRF (check
   `credential.getClientExtensionResults()`), fall back to the recovery
   code path.
2. Evaluate the PRF once with the salt to obtain the unlock secret:

   ```js
   const assertion = await navigator.credentials.get({
     publicKey: {
       challenge, allowCredentials: [{ id: credential.rawId, type: "public-key" }],
       extensions: { prf: { eval: { first: prfSalt } } },
     },
   });
   const unlockSecret = assertion.getClientExtensionResults().prf.results.first; // 32 bytes
   ```

   If using the recovery code instead: `crypto.getRandomValues(new Uint8Array(32))`,
   render it for the user, and use those bytes as the unlock secret.
3. Call the core: `CREATE_RECOVERY_BACKUP` (41), payload
   `[unlock_secret 32]` → response `[backup str32]`.
4. Upload the blob to the user's cloud under a fixed name, e.g.
   `stille-recovery-v1.bin`, together with a small public-metadata
   sidecar (PRF salt, creation date, core API version). The sidecar is
   not secret; the blob is (see §6).

### 4.3 Backup cadence (MUST)

- Re-run §4.2 steps 3–4 (CREATE + upload) after **profile-affecting**
  changes: name/avatar updates, contact accepted/added/deleted, block or
  unblock, core config change (server mode, relays, Tor).
- MUST NOT create/upload a backup per message or on a timer — history is
  not in the blob, message activity is not a trigger.
- Keep the previous blob version until the new upload succeeds
  (atomic replace), so a failed upload never destroys the last good backup.

### 4.4 Restore on a fresh device

1. Start the core: `stille-messenger-core serve`. With no seed file the daemon
   starts in **recovery mode** (ephemeral identity, no network threads).
   `GET_IDENTITY` returns `NOT_INITIALIZED` — that is the onboarding
   signal.
2. User picks the cloud account; the client downloads the blob (and the
   PRF salt sidecar).
3. Client derives the unlock secret: PRF eval with the saved salt, or the
   recovery code typed by the user.
4. Call `RESTORE_RECOVERY_BACKUP` (42), payload
   `[backup str32][unlock_secret 32]` → response
   `[bundle 64][fingerprint 32][name str16]`.
   - `OK`: profile is provisioned; the daemon brings networking up by
     itself. Show the restored name and let the user verify the
     fingerprint (same UX as first-time verification: voice/QR).
   - `BAD_RECOVERY` (18): wrong unlock secret or corrupt blob. Offer the
     fallback path (recovery code if PRF was used), then retry. Limit
     blind retries in UX (the failure is deterministic, not flaky).
   - `ALREADY_PROVISIONED` (20): a profile already exists on this device.
     Do not silently overwrite; offer an explicit destructive reset
     (delete `~/.stille-messenger` and restart the daemon) with a confirmation
     step.
   - Empty blob payload → `BAD_ARGS`; treat as a client bug, never send
     it.
5. After restore: normal bootstrap (§2). Expect empty history; contacts,
   routes, blocks and config are present.

### 4.5 Limits (document for UX)

- Backup blob ≤ 92 786 bytes; contacts ≤ 256; blocks ≤ 256;
  avatar ≤ 16 000 bytes; profile name ≤ 32 bytes.
- Restore works only into an **empty profile** (see §4.4 status mapping).
- One passkey+salt pair per backup. Rotating the unlock secret means
  re-running enrollment (CREATE with the new secret + upload) — the old
  blob becomes undecryptable garbage; keep blobs atomic-replaced (§4.3).

## 5. Security rules (MUST, all clients)

- **Never log** the unlock secret, PRF outputs, recovery code bytes, or
  blob contents. Treat the blob as opaque bytes: never parse, inspect,
  or render it.
- **Never display or export** `~/.stille-messenger/zig-seed` (the raw identity
  seed). The seed is the whole identity; the backup path exists exactly
  so the seed never has to be moved by hand.
- Wipe unlock-secret buffers after use (zero-fill; in JS drop all
  references to the `ArrayBuffer`).
- The PRF salt is public metadata; storing it next to the blob is fine.
- The recovery code is shown once at enrollment and never persisted,
  synced, or logged by the client.
- Transports other than the core's own (UDS for the core, OAuth for the
  user's cloud) MUST NOT be introduced by the client for identity
  material.
- On logout/"wipe device": delete local `~/.stille-messenger` (with confirmation);
  the cloud blob stays — that is the recovery path, and deleting it is a
  separate, explicit user action.

## 6. Implementation checklist

- [ ] UDS binary framing with 16-byte header, LE, request_id matching
- [ ] `GET_VERSION` gate on major mismatch (2.6.0)
- [ ] Event-driven UI, reconnect + re-bootstrap
- [ ] Onboarding: existing / new account (via `init`) / restore
- [ ] Passkey with PRF: salt generation, create with `prf: {}`, unlock
      with `prf.eval.first`, fallback to recovery code
- [ ] Cloud storage via `drive.appdata`-equivalent scope, atomic replace
- [ ] `CREATE_RECOVERY_BACKUP` after profile changes, not per message
- [ ] `RESTORE_RECOVERY_BACKUP` with full status mapping (§4.4)
- [ ] Fingerprint verification UX after restore
- [ ] Secrets never logged; blob opaque; seed never shown
