# Local Public-Key Credential Authentication Service

A self-contained, dependency-free (no external IdP / database / HSM) service
that implements WebAuthn-style **public-key credential registration and login
assertion verification**, backed solely by an atomically-written local JSON
file. Clients register an Ed25519 public key bound to a user; login proves
possession of the corresponding private key by signing a fresh server
challenge, while a per-credential monotonic signature counter detects cloned
or rolled-back authenticators.

Built with Spring Boot 3 / Java 17 (JDK-native Ed25519, no BouncyCastle).

---

## 1. Authentication flow

### 1.1 Registration

```
client                                    server
  |  POST /register/start {userId, origin}  |
  | --------------------------------------> |  create RegistrationSession:
  |                                         |    sessionId (128-bit random)
  |  {sessionId, challenge(256-bit),        |    challenge (256-bit random)
  |   expiresAt}                            |    bound to userId + origin
  | <-------------------------------------- |    persisted with TTL
  |                                         |
  | (client generates/has an Ed25519 key,   |
  |  signs canonical registration message)  |
  |                                         |
  |  POST /register/complete {              |
  |    sessionId, userId, origin,           |
  |    credentialId, publicKey (SPKI b64),  |
  |    signature (Ed25519 b64)}             |
  | --------------------------------------> | validate everything, verify sig,
  |                                         | consume session + insert cred
  |        {credentialId, userId, status}   | IN ONE ATOMIC TRANSACTION
  | <-------------------------------------- |
```

The client signs the canonical message:

```
LPKA-REG-v1 || len(origin)  || origin
            || len(userId)  || userId
            || len(challenge)|| challenge
            || len(credentialId)|| credentialId
            || len(publicKey)|| publicKey
```

Each segment is a 4-byte big-endian length followed by UTF-8 bytes, which
prevents field-boundary confusion / injection.

Validated before persistence, inside **one** store transaction:

1. field presence and format (`userId`, `credentialId`, base64 public key);
2. public key parses as an X.509/SPKI Ed25519 key;
3. session exists, is unconsumed, unexpired, bound to the same `userId`,
   and was issued to the same `origin`;
4. `credentialId` is globally unused (a credential belongs to exactly one
   user);
5. the signature verifies over the canonical message containing the server
   challenge.

Failure at any step aborts the transaction: **no half-written state**, and the
session is only consumed on success (sessions are single-use).

### 1.2 Login assertion

```
client                                    server
  |  POST /assert/start {userId, origin}    |
  | --------------------------------------> | new single-use challenge bound
  |  {challengeId, challenge, expiresAt}    | to userId + origin, TTL
  | <-------------------------------------- |
  |                                         |
  | (client chooses one of its credentials, |
  |  increments its signature counter,      |
  |  signs the canonical assertion message) |
  |                                         |
  |  POST /assert/verify {                  |
  |    challengeId, userId, origin,         |
  |    credentialId, counter, signature}    |
  | --------------------------------------> | look up ACTIVE credential owned
  |                                         | by user; consume challenge;
  |           {authenticated:true,...}      | verify signature; check counter
  | <--------------------------------------> | atomically
```

Canonical assertion message:

```
LPKA-AUTH-v1 || origin || userId || challenge || credentialId
             || counter as 8-byte big-endian
```

Rejected, with the challenge consumed atomically where applicable:

* unknown / expired / already-consumed challenge,
* challenge bound to a different user,
* origin mismatch,
* unknown credential or credential owned by another user,
* credential DISABLED or REVOKED,
* signature mismatch,
* reused / rolled-back counter (clone detection).

### 1.3 Credential lifecycle

* A user may register **many credentials**; any ACTIVE credential can log in.
* `POST /api/auth/credentials/{id}/disable?userId=...` — temporarily deactivates
  one credential; others are unaffected.
* `POST /api/auth/credentials/{id}/revoke?userId=...` — permanently deregisters
  one credential (also applied automatically on clone detection).
* `GET /api/auth/credentials?userId=...` — list the user's credentials.

---

## 2. Monotonic counter & clone detection

Each stored credential keeps:

* `counter` — high-water mark of accepted signature counters;
* `recentCounters` — a bounded LRU set (configurable window, default 128) of
  recently accepted values.

Rules in the single atomic assertion transaction:

| Situation | Result |
|---|---|
| `counter > highWater` | accept, advance high-water mark |
| `counter` already in `recentCounters` | **replay/clone** → credential REVOKED, `COUNTER_CLONE_DETECTED` |
| `highWater - window < counter <= highWater`, not seen | accept as a legitimate out-of-order concurrent assertion |
| `counter <= highWater - window` | **rollback/clone** → credential REVOKED, `COUNTER_CLONE_DETECTED` |

This serves all three required properties simultaneously:

1. **monotonic check** — counters normally strictly increase;
2. **clone/rollback detection** — reusing an observed counter, or jumping back
   farther than concurrent reordering can explain, revokes the credential;
3. **concurrent assertions** — the bounded gap window tolerates assertions that
   were signed with increasing counters but processed out of order by the
   server, so honest traffic is never falsely rejected. Replays are still
   caught because every exact value is remembered.

All read-check-update work runs under the store's single monitor and is
persisted before the response returns, so the counter update is **atomically
committed** with challenge consumption.

## 3. Sessions, expiry & concurrency

* Challenges are 256-bit `SecureRandom` values, IDs are 128-bit —
  unguessable.
* Registration sessions and assertion challenges are independent keyed entries:
  concurrent registrations/challenges for one user never overwrite each other.
* TTLs: `auth.registration-ttl-seconds` (default 300),
  `auth.assertion-ttl-seconds` (default 120).
* Expired entries are rejected on access and periodically reclaimed
  (`auth.cleanup-interval-ms`, default 60s) and on every restart.
* Challenges are single use: consumption removes the entry in the same
  transaction as the state change they authorize.

## 4. Persistence and restart recovery

* All state lives in one JSON file (`auth.store-file`, default
  `./data/auth-store.json`).
* Every successful mutation is written to a sibling temp file, `fsync`-ed, and
  atomically `rename(2)`-ed over the store file — a crash cannot leave a
  partially written JSON document.
* On startup the file is loaded; credentials, counters, status and in-flight
  (unexpired) sessions/challenges are fully restored. Consumed sessions are
  deleted on use, so they do not resurrect.

## 5. Trust boundaries

* **Server trust anchor:** `auth.expected-origin`. The server only mints
  challenges for this origin and requires every completion/verification to
  echo exactly that origin, which is also covered by the client signature.
  Requests claiming another origin are rejected with `ORIGIN_MISMATCH`.
* **Challenge freshness:** the server generates and stores every challenge;
  clients never choose challenges, and challenges are bound to user + origin,
  time-boxed and single-use.
* **Proof of possession:** the private key never leaves the client; the server
  only ever sees the SPKI public key and verifies signatures locally.
* **Ownership:** credential IDs are globally unique and every operation checks
  the `(userId, credentialId)` binding; a non-owner gets
  `CREDENTIAL_NOT_FOUND` rather than existence disclosure.
* **Local deployment note:** this service authenticates possession of
  credentials and binds them to user-supplied `userId`s. It deliberately has no
  user-registration / account-password layer, no transport security of its own
  and no rate limiting — front it with TLS and an account/authorization layer
  in a real deployment.

## 6. HTTP API

Base path: `/api/auth`. All request/response bodies are JSON.

| Method & path | Request | Success |
|---|---|---|
| `POST /register/start` | `{userId, origin}` | `200 {sessionId, challenge, expiresAt}` |
| `POST /register/complete` | `{sessionId, userId, origin, credentialId, publicKey, signature}` | `200 {credentialId, userId, status}` |
| `POST /assert/start` | `{userId, origin}` | `200 {challengeId, challenge, expiresAt}` |
| `POST /assert/verify` | `{challengeId, userId, origin, credentialId, counter, signature}` | `200 {authenticated, credentialId, counter}` |
| `GET /credentials?userId=` | – | `200 [{credentialId, userId, status, counter, createdAt, updatedAt}]` |
| `POST /credentials/{id}/disable?userId=` | – | `200 {status}` |
| `POST /credentials/{id}/revoke?userId=` | – | `200 {status}` |

Errors are `{ "code": "...", "message": "..." }`.

### Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `INVALID_REQUEST` | 400 | missing/malformed field, bad user/credential id format, bad JSON |
| `INVALID_PUBLIC_KEY` | 400 | public key is not a parseable Ed25519 SPKI key |
| `ORIGIN_MISMATCH` | 403 | origin is not the configured trusted origin, or does not match the session |
| `CHALLENGE_NOT_FOUND` | 404 | registration session / assertion challenge unknown or already consumed |
| `CHALLENGE_EXPIRED` | 410 | past its TTL |
| `CHALLENGE_CONSUMED` | 409 | marked used (defensive; normal replay surfaces as 404) |
| `CHALLENGE_USER_MISMATCH` | 403 | session/challenge is bound to another user |
| `CREDENTIAL_NOT_FOUND` | 404 | unknown credential, or credential not owned by the user |
| `CREDENTIAL_ALREADY_EXISTS` | 409 | credentialId already registered |
| `INVALID_SIGNATURE` | 401 | signature does not verify |
| `CREDENTIAL_REVOKED` | 403 | credential is DISABLED or REVOKED |
| `COUNTER_CLONE_DETECTED` | 401 | counter reused/rolled back; credential has been revoked |
| `INTERNAL_ERROR` | 500 | unexpected server-side failure |

## 7. Configuration

`src/main/resources/application.properties`:

```properties
auth.expected-origin=http://localhost:8080
auth.registration-ttl-seconds=300
auth.assertion-ttl-seconds=120
auth.cleanup-interval-ms=60000
auth.store-file=./data/auth-store.json
auth.recent-counters-window=128
```

## 8. Build & test

```bash
mvn spring-boot:run     # start service on :8080
mvn test                # 22 tests across service, web and restart recovery
```

Test coverage:

* registration success + format/origin/ownership/signature failures,
* assertion success, bad signature, wrong user, wrong origin,
* expiry (registration + assertion) and scheduled reclamation,
* challenge replay rejection,
* multiple credentials per user and independent disable/revoke,
* monotonic counter advances, clone/replay detection and auto-revocation,
* 8-thread concurrent assertions with out-of-order counters (no false
  positives, high-water mark correct),
* independent concurrent registrations and single-use completion,
* full restart recovery from the JSON file: credentials, counters, in-flight
  sessions/challenges, consumed-session non-resurrection and clone detection
  still enforced after reboot.

### Example client (test-style)

```java
KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
String publicKeyB64 = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(kp.getPublic().getEncoded());

// 1. start registration, then:
byte[] msg = MessageBuilder.registrationMessage(
        origin, userId, challenge, credentialId, publicKeyB64);
Signature s = Signature.getInstance("Ed25519");
s.initSign(kp.getPrivate()); s.update(msg);
String signatureB64 = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(s.sign());

// 2. login: MessageBuilder.assertionMessage(origin, userId, challenge,
//    credentialId, counter) signed the same way
```
