# Mira Cloud Service Credentials V0

This document describes the implemented OPS-008 run 1 and run 2 scope: the canonical service-credential contract, isolated Ed25519 signing/offline verification helpers, authenticated device-bound issuance, public verifier discovery, and the V0 signing-key overlap strategy. It also covers the OPS-019 account-owned Relay room/role admission layered on the same ticket contract, the GLN-013 Guanlan consumer credential, and the Who You mail-draft confirmation credential.

Full OPS-008 remains open. Cross-repository consumer implementation and production verification are intentionally not part of this repository change.

GLN-013 adds the Guanlan audience below. It is **not** claimed as working end-to-end: the Guanlan resource deployment, the GLN-012 registration projection and any live JWKS retrieval do not exist yet. See [docs/engineering/gln-013-guanlan-credential.md](engineering/gln-013-guanlan-credential.md).

The Who You audience adds a draft-bound send confirmation: Cloud Auth signs what the device-bound account session confirmed, while the Who You Worker verifies draft ownership, recomputes the content hash and atomically consumes the nonce. Cloud Auth stores no Who You draft, mailbox, message or user content. This credential is implemented and locally tested here, but Who You resource deployment and end-to-end sending remain outside this repository.

## Trust model

Cloud Session and service credentials are different layers:

1. `POST /v1/auth/login` (or device registration plus that session) establishes a revocable Cloud Session.
2. `POST /v1/service-credentials` exchanges a **device-bound** Cloud Session for one short-lived credential aimed at one explicit service audience.
3. The target service verifies the credential offline with Cloud Auth's published Ed25519 public keys. It never receives the user's password, the raw Cloud Session, or a universal bearer credential, and ordinary service requests do not call Cloud Auth.

A Cloud Session is accepted for credential issuance only when all of the following still hold at the final issuance boundary:

- the session id exists and its bearer secret hash matches;
- the session is not revoked and is not expired;
- the account is allowed and not disabled;
- `sessions.device_id` is non-null and refers to a device owned by the same account;
- that Mira Device is not revoked.

The authority check and signing happen inside one SQLite `BEGIN IMMEDIATE` transaction. Logout, session renewal, device revocation, account disable, and other writer operations cannot interleave between the final check and signing. A legacy Web session with `device_id IS NULL` remains valid for normal web login/restore/renewal but cannot obtain a service credential; it receives `403 SERVICE_CREDENTIAL_DEVICE_REQUIRED`.

The endpoint derives account id, device id, issuer, key id, and scope on the server. It never trusts client-supplied identity, issuer, key id, audience beyond the supported values, or business permissions, and it never returns or forwards the original Cloud Session.

### Relay ticket entitlement (OPS-019)

A syntactically valid Relay room and role are not authorization. For the Relay transport audience, Cloud Auth resolves the requested room against the authoritative OPS-018 Desktop Host room association inside the same issuance transaction and derives the caller device and platform from the Cloud Session. The ticket is issued only when all of the following hold:

- `role = "host"`: the session is bound to the Desktop device that owns the room, that device belongs to the same account, and the Host's registration, owning session and presence lease are currently `available`;
- `role = "client"`: the session is bound to a Mobile device of the same account as the room's Host, and the room association is currently `available`.

Unknown, old, revoked or offline rooms, foreign accounts, a non-owner Desktop claiming `host`, a Mobile claiming `host`, and a Desktop claiming `client` all fail closed with `403 SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED`. The denial does not reveal whether the room exists or who owns it, and ticket issuance never creates a room. Request body fields such as `account_id`, `device_id`, `platform` or an alternate role cannot override the server-side association. This ticket is transport-only: it does not mean Relay accepted a connection, and it never grants Host `tools:invoke`.

### Guanlan admission (GLN-013)

A verified device-bound Cloud Session is necessary but not sufficient. For the Guanlan audience, credential issuance additionally requires that Cloud Auth's own durable registration projection for that account reports `delivered`:

- `delivered` → issuance proceeds;
- `pending`, `delivering`, `withheld`, `failed`, or no row → `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY`, no token;
- the projection table itself absent → also `409`, because absence is "unknown", never "allowed".

This projection is the GLN-012 registration outbox (`apps/api/src/service-credentials/guanlan-space-readiness.ts`, table `guanlan_registration_outbox`). Cloud Auth only reads it and stores no Guanlan account, consumer, news or ledger data. The authoritative `guanlan_accounts` / `guanlan_consumers` rows remain Guanlan's.

The check runs inside the same `BEGIN IMMEDIATE` issuance transaction as the session/device/account authority check, so a concurrent disable, revoke or registration-state change cannot interleave between the decision and signing. Denials are bounded and do not echo the account, the consumer or the registration state.

Consumer identity and write authority are derived, not accepted from the client: `consumer_id` is the verified account id, and `guanlan.write` appears only when the caller explicitly requested it alongside `guanlan.read`. There is no path from read-only to write and no path from one account's session to another account's consumer.

**Availability caveat:** GLN-012 (the registration outbox) is merged into `dev` (`931ae6c`), so the projection exists in deployment. An account starts at `pending` and only a confirmed delivery moves it to `delivered`, so Guanlan credential issuance fails closed with `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY` until the Guanlan receiver delivers that account. Credential issuance itself is implemented and tested; it is **not** proven end-to-end against a live Guanlan deployment.

## Contract

### Issuer and audiences

| Field | Value |
| --- | --- |
| Issuer (`iss`) | `mira:cloud-auth` |
| Cloud Shiyan audience | `mira:cloud-shiyan` |
| Hosted Relay transport audience | `mira:cloud-relay-transport` |
| Guanlan resource audience | `mira:cloud-guanlan` |
| Who You mail audience | `mira:who-you` |

The issuer is deployment-neutral. Services must configure the trusted issuer explicitly when verifying; they must never derive trust from the token's own `iss` claim.

The audiences are intentionally non-interchangeable. A Shiyan verifier accepts only `mira:cloud-shiyan`; a Relay verifier accepts only `mira:cloud-relay-transport`; a Guanlan verifier accepts only `mira:cloud-guanlan`; a Who You verifier accepts only `mira:who-you`. A valid credential for one service fails verification at the others.

### Scopes

Each audience has a canonical least-privilege scope set, not an open scope list. Guanlan has a mandatory read gate plus an optional independent write authority; Who You has a read gate, an optional draft-write authority, and a standalone send-confirmation authority that never grants read or write.

| Audience | Scope |
| --- | --- |
| `mira:cloud-shiyan` | `shiyan:authenticate` |
| `mira:cloud-relay-transport` | `relay:transport` |
| `mira:cloud-guanlan` | `guanlan.read` (mandatory) and, only when explicitly requested, `guanlan.write` |
| `mira:who-you` | `whoyou.read` (default), `whoyou.read` + `whoyou.mail.write` when explicitly requested, or `whoyou.mail.send` alone together with a draft-bound confirmation |

These scopes assert only "Cloud Auth authenticated this account/device to this service" or "this is a transport connection ticket" or "this user session confirmed this exact draft revision". They do not grant Shiyan business-resource authorization and do not grant Remote Host Browser, Terminal, Agent, Thread, tool, or other business capabilities. `guanlan.read` admits the caller to the Guanlan MCP resource; `guanlan.write` is checked by each decision tool and is never implied by read. `whoyou.read` admits the caller to the Who You `/mcp` resource; `whoyou.mail.write` is checked by each draft tool; `whoyou.mail.send` is a separate credential argument to the send tool and is never accepted as a `/mcp` bearer.

Unsupported, missing, duplicate, cross-audience, or additional scopes are rejected by the canonical schema before any service consumes the claims.

### JWT header

The only accepted header is:

```json
{ "alg": "EdDSA", "typ": "JWT", "kid": "<bounded key id>" }
```

- `alg` is Ed25519 (`EdDSA`) only. `none`, HMAC, RSA, ECDSA, and other algorithms are rejected.
- `typ` must be `JWT`.
- `kid` is a bounded `[A-Za-z0-9._-]{1,64}` identifier.
- The verifier looks up `kid` only in an explicitly injected trusted key map. It never fetches keys over the network and never trusts `kid` as authority by itself.

### Claims

Shiyan credential:

```json
{
  "iss": "mira:cloud-auth",
  "sub": "<Mira Cloud account id>",
  "device_id": "<Mira Device id>",
  "aud": "mira:cloud-shiyan",
  "scope": ["shiyan:authenticate"],
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000300
}
```

Hosted Relay transport ticket:

```json
{
  "iss": "mira:cloud-auth",
  "sub": "<Mira Cloud account id>",
  "device_id": "<Mira Device id>",
  "aud": "mira:cloud-relay-transport",
  "scope": ["relay:transport"],
  "relay": {
    "room": "room-7f3a",
    "role": "client"
  },
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000300
}
```

- `sub` is the Mira Cloud account. `device_id` separately asserts the Mira Device that the credential was issued for.
- `iat`, `nbf`, and `exp` are JWT NumericDate seconds. The schema requires `nbf >= iat` and `exp > nbf`.
- Unknown claims are rejected by the strict schema.
- Relay `room` is a bounded transport identifier and `role` is `client` or `host`. These are transport peer semantics only; the ticket cannot encode or imply Host tool or business authorization.
- Ticket expiry gates establishing a new connection with that ticket. It does not by itself require terminating an already-established Relay WebSocket; connection lifecycle remains Relay-owned.

Guanlan consumer credential (read-only sample; the write variant adds `"guanlan.write"` after `"guanlan.read"`):

```json
{
  "iss": "mira:cloud-auth",
  "sub": "<Mira Cloud account id>",
  "device_id": "<Mira Device id>",
  "aud": "mira:cloud-guanlan",
  "scope": ["guanlan.read"],
  "consumer_id": "<Mira Cloud account id>",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000300
}
```

- `consumer_id` is derived by Cloud Auth from the verified, device-bound Cloud Session. It is one stable Guanlan consumer per Mira Cloud account (`consumer_id == sub`), so the same account keeps one consumption ledger across its devices and sessions. A request body field named `consumer_id` is rejected by the strict request schema; no client can name another account's consumer.
- Guanlan ignores `device_id` for authorization. It is kept because every service credential carries it and it makes incident evidence precise.
- Guanlan's own principal tables (`guanlan_accounts`, `guanlan_consumers`) remain Guanlan-owned. Cloud Auth stores no Guanlan business data and creates no consumer table.

Who You consumer credential (read-only sample; the write variant adds `"whoyou.mail.write"` after `"whoyou.read"`):

```json
{
  "iss": "mira:cloud-auth",
  "sub": "<Mira Cloud account id>",
  "device_id": "<Mira Device id>",
  "aud": "mira:who-you",
  "scope": ["whoyou.read"],
  "consumer_id": "<Mira Cloud account id>",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000300
}
```

Who You send confirmation (standalone scope, no read or write):

```json
{
  "iss": "mira:cloud-auth",
  "sub": "<Mira Cloud account id>",
  "device_id": "<Mira Device id>",
  "aud": "mira:who-you",
  "scope": ["whoyou.mail.send"],
  "consumer_id": "<Mira Cloud account id>",
  "confirmation": {
    "actor": "user",
    "draft_id": "dr_0123456789abcdef",
    "draft_version": 7,
    "content_hash": "<lowercase sha256 hex>",
    "nonce": "<bounded base64url nonce>"
  },
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000300
}
```

- `consumer_id` is derived from the verified, device-bound Cloud Session and must equal `sub`; a request body field named `consumer_id` is rejected by the strict request schema.
- `confirmation` is present only with the standalone `whoyou.mail.send` scope and is required there. It binds one draft id, one positive draft version, one lowercase SHA-256 content hash and one bounded nonce; the server rejects unknown keys.
- Cloud Auth does not verify that the draft exists, that the account owns it, or that the hash matches stored content. It asserts only that this device-bound account session confirmed that exact content identity. Who You remains authoritative for draft ownership, version and hash checks, and must atomically consume the nonce before any send side effect.
- The request body never carries draft binding for Cloud Auth to trust blindly beyond signing; a client can obtain a confirmation only for content it presented, and Who You rejects any confirmation that does not match its own stored draft.

## HTTP API

### POST /v1/service-credentials

Requires `Authorization: Bearer <Cloud Session>` for a device-bound, non-revoked session. Relay requests additionally require the caller device/platform and requested room/role to satisfy the OPS-019 admission rules above.

Shiyan request:

```json
{ "audience": "mira:cloud-shiyan" }
```

Hosted Relay request:

```json
{
  "audience": "mira:cloud-relay-transport",
  "relay": { "room": "room-7f3a", "role": "client" }
}
```

Guanlan request (`scopes` is optional and defaults to read-only):

```json
{ "audience": "mira:cloud-guanlan", "scopes": ["guanlan.read", "guanlan.write"] }
```

A Guanlan request succeeds only when the GLN-012 registration projection reports `delivered` for the calling account; otherwise it returns `409 SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY` and no token. See "Guanlan admission" below.

Who You read request (default scope):

```json
{ "audience": "mira:who-you" }
```

Who You draft-write request:

```json
{ "audience": "mira:who-you", "scopes": ["whoyou.read", "whoyou.mail.write"] }
```

Who You send confirmation request:

```json
{
  "audience": "mira:who-you",
  "confirmation": {
    "actor": "user",
    "draft_id": "dr_0123456789abcdef",
    "draft_version": 7,
    "content_hash": "<lowercase sha256 hex>",
    "nonce": "<bounded base64url nonce>"
  }
}
```

`scopes` and `confirmation` are mutually exclusive. A Who You request that asks for `whoyou.mail.send` as a scope, or that sends an invalid draft binding, returns `400 SERVICE_CREDENTIAL_INVALID_REQUEST`.

Success returns only the short-lived credential and necessary metadata:

```json
{
  "token": "<compact EdDSA JWS>",
  "tokenType": "Bearer",
  "audience": "mira:cloud-shiyan",
  "expiresAt": "2026-10-24T10:05:00.000Z"
}
```

Error codes:

| Status | Code |
| --- | --- |
| 400 | `SERVICE_CREDENTIAL_INVALID_REQUEST` |
| 401 | `SERVICE_CREDENTIAL_REAUTH_REQUIRED` |
| 403 | `SERVICE_CREDENTIAL_DEVICE_REQUIRED` |
| 403 | `SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED` |
| 409 | `SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY` |
| 503 | `SERVICE_CREDENTIAL_UNAVAILABLE` |
| 500 | `SERVICE_CREDENTIAL_INTERNAL_ERROR` |

A missing or malformed bearer, unknown session, expired session, revoked session, rotated-away old session secret, revoked device, disabled account, or denied account all return `401 SERVICE_CREDENTIAL_REAUTH_REQUIRED` without leaking which check failed.

A valid device-bound session that is not entitled to the requested Relay room/role returns `403 SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED` with one bounded message regardless of whether the room is unknown, offline, revoked or owned by another account. The route logs only a non-secret denial event; it does not log the Cloud Session, room, role or account.

### GET /.well-known/jwks.json

Returns only trusted Ed25519 public verification keys:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "use": "sig",
      "alg": "EdDSA",
      "kid": "cloud-auth-2026-10",
      "x": "<base64url public key>"
    }
  ]
}
```

The response is cacheable for 300 seconds in V0. It contains the active signing key first, followed by configured **verification-only public keys** (old retiring keys or the future key pre-published before rotation). The existing configuration field is named `RETIRING_PUBLIC_KEYS` for compatibility; it may temporarily hold the **next public key** during the pre-publication phase. It never contains private key material. When signing/verification material is not fully configured, credential issuance and JWKS return `503 SERVICE_CREDENTIAL_UNAVAILABLE`.

## Signing configuration

Signing material is injected explicitly from deployment configuration; it is never read from token contents, committed repository files, or host credentials. Environment variables:

| Variable | Purpose |
| --- | --- |
| `MIRA_AUTH_SERVICE_CREDENTIAL_ACTIVE_KID` | Active signing key id. |
| `MIRA_AUTH_SERVICE_CREDENTIAL_ACTIVE_PRIVATE_KEY` | Active Ed25519 private key PEM. Secret. Never logged or returned. |
| `MIRA_AUTH_SERVICE_CREDENTIAL_RETIRING_PUBLIC_KEYS` | JSON object of verification-only Ed25519 **public** PEMs. Use for old retiring keys and for the next key's public half during pre-publication. Private PEMs are rejected. |
| `MIRA_AUTH_SERVICE_CREDENTIAL_TTL_SECONDS` | Optional TTL, default 300, maximum 600. |

PEM values may use real newlines or escaped `\n` sequences from environment files. If these variables are absent, or if any supplied key id / PEM / TTL / JSON value is invalid, service-credential issuance and JWKS fail closed. This does **not** disable account login, `/health`, `/ready`, device management, or the web application. Invalid configuration is reported only as `SERVICE_CREDENTIAL_UNAVAILABLE`.

No production private key, real key id, or deployment secret is committed by this repository.

## Verification

Implementation:

- `apps/api/src/service-credentials/signer.ts`
- `apps/api/src/service-credentials/verifier.ts`
- `apps/api/src/service-credentials/keyring.ts`
- `apps/api/src/service-credentials/service.ts`
- `apps/api/src/service-credentials/routes.ts`
- `apps/api/src/service-credentials/jwt.ts`
- `packages/contracts/src/service-credential.ts` (browser-safe canonical schemas and literals)

Verification is offline and fail-closed. It rejects:

- a token that is not a three-segment compact JWS;
- a malformed header, any algorithm other than `EdDSA`, any `typ` other than `JWT`, or an invalid `kid`;
- a `kid` absent from the explicitly trusted key map;
- an invalid, unsigned, or modified signature;
- claims that do not satisfy the strict canonical schema;
- an issuer other than the explicitly configured trusted issuer;
- an audience other than the verifier's single configured audience;
- missing or unexpected scope;
- a Guanlan credential without a non-blank `consumer_id`, with a blank, whitespace-padded or over-long consumer, with a write-only scope, or with a scope order other than read then read+write;
- a Who You credential without `consumer_id == sub`; with a non-canonical scope set, reversed scope order, or `whoyou.mail.send` combined with read/write; with `whoyou.mail.send` but no `confirmation`; with `confirmation` on a read or write credential; or with an unknown confirmation key, a non-`user` actor, an out-of-range draft version, a non-lowercase or non-64-hex content hash, or an out-of-bounds nonce;
- `iat` in the future, `nbf` not yet reached, `exp` passed, or lifetime above the verifier limit;
- a Relay verifier that omits the expected room/role, or a ticket whose room or role does not match that connection context;
- an invalid verifier clock, so expiry cannot be checked safely.

A Relay consumer must pass the actual expected room and role when accepting a connection. Omitting that context fails with `INVALID_VERIFIER_CONFIG` rather than checking only ticket structure. The Relay service remains responsible for its own transport connection lifecycle and any further business authorization.

### Consumer checklist

Consumers should share the canonical literals/schemas from `@uichat-mira/cloud-auth-contracts` rather than redefining claim names, audiences, scopes, or header rules. A verification integration has this shape:

```ts
// Shiyan: accept only the Shiyan audience and its one scope.
const shiyan = verifyServiceCredential(credential, {
  issuer: SERVICE_CREDENTIAL_ISSUER,
  audience: CLOUD_SHIYAN_AUDIENCE,
  publicKeys: trustedKeysFromJwks, // explicit, from the trusted JWKS URL/cache
});

// Relay: additionally bind the ticket to the actual transport connection.
const relay = verifyServiceCredential(connectionCredential, {
  issuer: SERVICE_CREDENTIAL_ISSUER,
  audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
  publicKeys: trustedKeysFromJwks,
  expectedRelay: { room: actualRequestedRoom, role: actualPeerRole },
});

// Guanlan: accept only the Guanlan audience; require the read gate and treat
// guanlan.write as an independent, tool-level authority.
const guanlan = verifyServiceCredential(resourceCredential, {
  issuer: SERVICE_CREDENTIAL_ISSUER,
  audience: CLOUD_GUANLAN_AUDIENCE,
  publicKeys: trustedKeysFromJwks,
});
if (!guanlan.claims.scope.includes("guanlan.read")) throw new Error("not admitted");

// Who You: read/write on `/mcp`, and a separate send confirmation.
const whoYou = verifyServiceCredential(credential, {
  issuer: SERVICE_CREDENTIAL_ISSUER,
  audience: CLOUD_WHO_YOU_AUDIENCE,
  publicKeys: trustedKeysFromJwks,
});
if (!whoYou.claims.scope.includes("whoyou.read")) throw new Error("not admitted");

const confirmation = verifyServiceCredential(confirmationCredential, {
  issuer: SERVICE_CREDENTIAL_ISSUER,
  audience: CLOUD_WHO_YOU_AUDIENCE,
  publicKeys: trustedKeysFromJwks,
});
// Who You must check draft ownership, version and content hash, then consume
// the nonce atomically before any send side effect.
if (!confirmation.claims.scope.includes("whoyou.mail.send")) throw new Error("not a confirmation");
```

The tests under `apps/api/tests/contract` and `apps/api/tests/integration` are the executable examples for all audiences, including negative cases. They generate ephemeral Ed25519 key pairs at test time; no key material is committed.

## Lifetime and revocation limitation

The default TTL is 300 seconds; the maximum issuance and verification lifetime is 600 seconds. These are reviewed V0 implementation bounds, not permanent product truth.

Revoking an account, device, or Cloud Session stops **future issuance**. An already-issued service credential remains verifiable until its `exp` unless a consumer adds an explicit online revocation check. V0 bounds this exposure with short lifetimes; production TTL selection must account for this remaining-lifetime risk and is still a maintainer decision.

This is the agreed GLN-013 semantics: no `jti`, no revocation table and no online introspection were added. Revocation is `short TTL + issuance-time re-check`. For the Guanlan audience the recommended TTL is **at most 300 seconds** (the implemented maximum of 600 seconds is unchanged), and a Guanlan credential is accepted for at most its remaining lifetime after an account, device or session is revoked.

Who You follows the same model. Cloud Auth signs the confirmation nonce but stores no nonce, draft or send state; Who You must reject a replayed nonce atomically, so a revoked account or device stops future confirmations while an already-issued one remains usable only until its `exp` and its first consumption.

## V0 key rotation

`kid` is carried in the JWT header; only the active key signs new credentials. To avoid rejecting newly issued credentials on a consumer holding a still-valid cached JWKS, **pre-publish the new public key before activating its private key**. The V0 procedure uses the existing `RETIRING_PUBLIC_KEYS` field for public verification-only keys in **both** directions:

1. Generate the new Ed25519 pair outside this repository. Keep the **old** active private key/signing `kid` unchanged. Add **only the new public key** under its future `kid` to `MIRA_AUTH_SERVICE_CREDENTIAL_RETIRING_PUBLIC_KEYS` and deploy this JWKS pre-publication phase.
2. Confirm the updated JWKS with **both public keys** is reachable on every serving instance. Wait at least the published **300-second cache lifetime plus deployment propagation** so consumers with a previously cached old-only JWKS can refresh before any new-`kid` credentials are issued. Do not advance while an old-only JWKS response can still be served.
3. Switch `ACTIVE_KID` / `ACTIVE_PRIVATE_KEY` to the **new** pair; keep the **old public key** in `RETIRING_PUBLIC_KEYS`. New tokens use the new `kid`, while both the pre-switch cached JWKS and the new JWKS verify either key. If the switch is rolled back, keep both public keys published throughout the rollback and its cache window.
4. Once the last old-key token could have expired, allow at least the maximum **600-second token lifetime**, the **300-second JWKS cache lifetime**, and deployment propagation after the last old signature / old-only JWKS response. Then remove the old public key and deploy. Consumers must refresh JWKS on its cache schedule; an unknown `kid` must fail verification, never fall back to another key.

The unit rotation test constructs a cached pre-switch JWKS, signs tokens with both old and new active keys, verifies both with cached and refreshed key sets, and confirms the old key becomes unknown after retirement. **Never place any private PEM in the verification-only list; config containing a private PEM fails closed.** This repository does not rotate production keys or control consumer caches; the real SHY/REL deployment rollout and cache verification remain required before production promotion.

## Not implemented

- Real production key generation, secret provisioning, deployment, or rotation.
- Changes to Cloud Shiyan, hosted Relay, Desktop, or Mobile repositories.
- Mobile/Desktop credential-acquisition UI or wiring.
- Shiyan business-resource authorization.
- Relay WebSocket connection admission in the Relay service (REL-001) or Relay frame authorization/Remote Host Browser/Terminal/Agent/Thread capabilities.
- Per-request Cloud Auth introspection or online revocation checks by consumers.
- Universal service tokens.
- Guanlan space provisioning, `guanlan_accounts` / `guanlan_consumers` rows or any Guanlan business data in this repository (owned by GLN-012 and Guanlan).
- A live Guanlan `/mcp` endpoint, live JWKS retrieval from Cloud Auth, or any verified end-to-end Guanlan call.
- Any Who You deployment, mailbox or draft store, relay, Email Routing, real send, nonce consumption, or verified end-to-end Who You call. This repository only issues and verifies the credential shape.
- Public registration, OAuth, Passkeys, self-service recovery, Redis, PostgreSQL, hardware identifiers, or device proof-of-possession.

Cross-repository consumer implementation and evidence from SHY-001 and REL-001 remain required before production promotion.
