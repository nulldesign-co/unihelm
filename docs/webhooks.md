# Webhooks

Ferrum will never grow a billing module. Spec §2.4 says so explicitly — *"No
billing/invoicing — expose a clean API + webhooks so WHMCS/FOSSBilling can
integrate later"* — which makes this page the other half of that sentence:
everything somebody needs to receive Ferrum's events and be sure they came from
Ferrum.

This document is the contract. If you are implementing the receiving side, you
should not have to read any Rust.

---

## 1. Registering an endpoint

```
POST /api/webhooks
{
  "url": "https://billing.example.com/ferrum/events",
  "events": ["backup.failed", "subscription.suspended"]
}
```

The response carries the signing secret **exactly once**:

```json
{
  "webhook": { "id": 3, "url": "...", "events": [...], "active": true, ... },
  "secret": "9f2c…64 hex characters…",
  "signature_scheme": "HMAC-SHA256 over `v1:<X-Ferrum-Timestamp>:<raw body>` …"
}
```

The secret is sealed with the panel master key (XChaCha20-Poly1305) before it
is stored and is never returned again — not by `GET /api/webhooks`, not in a
task log, not in the audit trail. If you lose it, rotate it:
`PUT /api/webhooks/{id}` with `"rotate_secret": true` mints a new one and
invalidates the old.

Subscribe to `["*"]` for every event, including ones added later. That is
opt-in rather than the default, because a receiver that has never been written
against an event still receives it — fine for a log sink, wrong for a state
machine.

---

## 2. What a delivery looks like

```
POST /ferrum/events HTTP/1.1
Content-Type: application/json
User-Agent: ferrum-panel/0.1.0
X-Ferrum-Event: backup.failed
X-Ferrum-Delivery: 4821
X-Ferrum-Timestamp: 1764250800
X-Ferrum-Signature: v1=3f0a…64 hex characters…

{"event":"backup.failed","id":4821,"at":"2026-08-28T09:00:00Z","data":{ … }}
```

| Header | Meaning |
|---|---|
| `X-Ferrum-Event` | The event name. Also in the body; the header is there so a proxy or a router can dispatch without parsing. |
| `X-Ferrum-Delivery` | The delivery id. **Stable across retries** — this is your de-duplication key. |
| `X-Ferrum-Timestamp` | Unix seconds, UTC, at the moment of *this attempt*. Covered by the signature. |
| `X-Ferrum-Signature` | `v1=<lowercase hex HMAC-SHA256>`. |

The body is the same four fields for every event: `event`, `id`, `at` (RFC 3339,
UTC) and `data`, whose shape depends on the event.

---

## 3. Verifying the signature

Three steps, in this order:

1. **Read the raw body as bytes.** Do not parse the JSON first. A receiver that
   deserialises and re-encodes before verifying will fail on key order and
   whitespace — the panel signs exactly the bytes it puts on the wire.
2. **Rebuild the signed string:** the ASCII text

   ```
   v1:<X-Ferrum-Timestamp>:<raw body>
   ```

   — the literal `v1`, a colon, the timestamp header verbatim, a colon, then the
   body bytes.
3. **Compute `HMAC-SHA256(secret, signed_string)`** and compare it, in constant
   time, against the hex after `v1=` in `X-Ferrum-Signature`. The MAC key is the
   secret string **exactly as the panel showed it** — ASCII bytes, not
   hex-decoded first.

Then **reject anything older than your tolerance** (five minutes is the usual
choice) by comparing `X-Ferrum-Timestamp` against your own clock. This is the
step that makes the timestamp worth having: without it, a captured request can
be replayed forever. The timestamp is inside the MAC precisely so an attacker
cannot edit it.

### Worked example

These exact values are pinned by a test in `crates/ferrum-ops/src/webhook.rs`
(`the_documented_signature_vector_still_holds`), so they will not drift:

```
secret     topsecret
timestamp  1700000000
body       {"event":"site.created"}

signed     v1:1700000000:{"event":"site.created"}
signature  v1=364d1332b8987cf01317f9300e328255efac8a800eaedb815da6e1b4b339449f
```

### Receiver sketches

Python:

```python
import hmac, hashlib, time

def verify(secret, headers, raw_body, tolerance=300):
    ts = int(headers["X-Ferrum-Timestamp"])
    if abs(time.time() - ts) > tolerance:
        return False                      # replay, or a badly wrong clock
    signed = b"v1:%d:" % ts + raw_body
    expected = "v1=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-Ferrum-Signature"])
```

PHP:

```php
function ferrum_verify(string $secret, array $h, string $body, int $tol = 300): bool {
    $ts = (int) $h['X-Ferrum-Timestamp'];
    if (abs(time() - $ts) > $tol) { return false; }
    $expected = 'v1=' . hash_hmac('sha256', "v1:$ts:$body", $secret);
    return hash_equals($expected, $h['X-Ferrum-Signature']);
}
```

Node:

```js
const crypto = require("crypto");
function verify(secret, headers, rawBody, tolerance = 300) {
  const ts = Number(headers["x-ferrum-timestamp"]);
  if (Math.abs(Date.now() / 1000 - ts) > tolerance) return false;
  const mac = crypto.createHmac("sha256", secret)
    .update(`v1:${ts}:`).update(rawBody).digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(`v1=${mac}`), Buffer.from(headers["x-ferrum-signature"]));
}
```

### Why `v1=`

The prefix is there from the first release so that changing the scheme later is
additive: a future panel would send `X-Ferrum-Signature: v1=…,v2=…`, and a
receiver picks the version it understands and ignores the rest. A scheme with no
version in it can only ever be replaced by a flag day.

---

## 4. Delivery semantics

**At-least-once, never exactly-once.** A delivery is marked delivered only after
the panel *sees* a 2xx. A response lost on the wire produces a second POST with
the same `X-Ferrum-Delivery` id and a byte-identical body. Make your handler
idempotent, keyed on that id.

**The payload is frozen at emit time.** A retry re-sends the bytes that were
built when the event happened — not a fresh look at current state. A redelivery
is a redelivery.

**Only 2xx counts.** Everything else is a failure worth retrying, 4xx included:
a 401 or a 404 usually means the receiver is misconfigured, and retrying gives
whoever is fixing it a window in which the event still arrives.

**Nothing you return is interpreted.** The response body is discarded unread.

**Retries follow a bounded exponential curve:**

| Attempt | Waits before it |
|---|---|
| 1 | — (immediately, on the next delivery tick) |
| 2 | 30 s |
| 3 | 60 s |
| 4 | 120 s |
| 5 | 240 s |
| 6 | 480 s |

After the sixth attempt the delivery is abandoned and recorded as `failed`. The
whole curve is under sixteen minutes.

**A dead endpoint is switched off, not retried forever.** Consecutive failed
attempts are counted per hook and reset by any 2xx. At **20** consecutive
failures the hook is deactivated with a reason recorded in `disabled_reason`,
and everything still queued for it is abandoned rather than left to replay at an
endpoint that has moved on. Re-enabling the hook
(`PUT /api/webhooks/{id}` with `"active": true`) clears the streak.

`webhook.test` counts too: it is a real POST to a real endpoint, so twenty
failed tests against a dead host teach the panel exactly what twenty failed
deliveries would.

**Redirects:** at most one hop, and never a downgrade to plain HTTP. A webhook
URL usually carries its own authorization in the path, and following a downgrade
would hand that credential to anyone on the wire.

**Timeout:** 10 seconds per attempt. Acknowledge fast and do your work
afterwards.

---

## 5. The event catalogue

The list is **closed**: `webhook.set` refuses a name that is not on it, because
a typo in an event name is otherwise a hook that looks configured and never
fires.

| Event | When | `data` carries |
|---|---|---|
| `account.created` | A new account was provisioned | account id, role |
| `quota.near_limit` | A tenant crossed the near-full line on its disk quota | subscription id, used and limit bytes |
| `certificate.renewed` | A certificate was issued or renewed | certificate id, site id, domains, `not_after`, `days_valid` |
| `backup.completed` | A backup run finished | run id, repo id, scope, subscription id, snapshot id, bytes |
| `backup.failed` | A backup run failed | run id, repo id, scope, subscription id, error |
| `subscription.suspended` | A subscription was suspended | subscription id, Linux account, reason, sites switched |
| `site.created` | A site went live | site id, domain, subscription id |
| `site.deleted` | A site was removed | site id, domain, whether files were purged |

Two of these — `account.created` and `quota.near_limit` — are declared and
deliverable but **have no emitter in this build**: account creation happens in
the installer rather than through a registered operation, and the near-quota
condition needs a periodic per-tenant evaluation that does not exist yet. A hook
may subscribe to them today and will start receiving them the moment the emitter
lands; nothing about the contract changes.

`webhook.test` is *not* in the catalogue and cannot be subscribed to. A test
delivery carries `"event": "webhook.test"` and `"id": 0`, so a receiver
switching on `event` can tell a drill from the real thing.

---

## 6. Operational notes

- **Limits.** 20 hooks per account. Every hook multiplies every event by one
  more HTTP request, and an unbounded fan-out is a way to make the panel attack
  something on somebody else's behalf.
- **Loopback and private addresses are allowed.** Only an account holding
  `server_manage` can register a hook, that account already has root on the
  machine, and relaying through `http://127.0.0.1:9000/hook` is a legitimate and
  common setup. What is refused is what somebody gets wrong by pasting: a
  non-HTTP scheme, whitespace, a control character, an absurd length.
- **History.** `GET /api/webhooks/{id}` returns the last 50 deliveries with
  their attempt count, response status and last error. Terminal deliveries are
  purged on the same daily sweep and the same retention setting as the audit log
  (`audit.retention_days`, 180 days by default); pending deliveries are never
  purged.
- **Restores.** The signing secrets are sealed with the master key in
  `/etc/ferrum/secret.key`. A database restored without that file has hooks
  whose secrets cannot be opened; the delivery loop disables such a hook with a
  reason rather than POSTing anything unsigned.
