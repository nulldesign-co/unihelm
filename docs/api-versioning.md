# API stability and versioning

Spec §14 Phase 6 asks for a *"public API stability guarantee + versioning"*, and
spec §2.6 explains why it has to be real: **everything the UI can do, it does
through the REST API**. There is no private channel. That means the API is not a
convenience wrapper somebody bolted on — it is the product surface, and a
third-party client is as first-class a consumer as the panel's own React app.

This page is the guarantee.

---

## The version

`GET /api/openapi.json` carries an explicit `info.version`:

```json
{ "openapi": "3.1.0", "info": { "title": "Unihelm Panel API", "version": "1.0.0", … } }
```

It is **semver**, and it is **not** the panel's release version. Tying the two
would mean every panel release claimed an API change, which makes the number
useless for the one thing it is for: telling an integrator whether they have to
read anything. A panel may ship a dozen releases without the API version moving.

The constant lives in `crates/unihelm-web/src/routes/openapi.rs` (`API_VERSION`)
and a test asserts the document declares it, that it is well-formed semver, and
that it has not silently become the crate version.

---

## What each bump means

### Patch — `1.0.0 → 1.0.1`

The document got more accurate. Nothing about the running API changed.

- A description, summary or example was corrected or improved.
- A response field that was always present was finally written down.
- A status code the endpoint always returned was added to its `responses`.

**A client never has to do anything.**

### Minor — `1.0.0 → 1.1.0`

Something was **added**. Everything that worked before still works.

- A new endpoint.
- A new **optional** request field, or a new query parameter with a default.
- A new field in a response body.
- A new value in an enum that the documentation already describes as open —
  a new `ErrorCode`, a new operation name, a new webhook event name, a new
  plugin extension point.
- A new tag, a new security scheme *alongside* the existing ones.

**A client written against an earlier minor keeps working**, provided it ignores
fields it does not recognise. That proviso is on you: a client that rejects
unknown response fields is a client that will break on a minor bump, and every
generated client we know of tolerates them by default.

### Major — `1.0.0 → 2.0.0`

Something a client could depend on changed or went away.

- An endpoint removed, or its path or method changed.
- A request field that was optional becoming required.
- A response field removed, renamed, or changing type.
- The **meaning** of a field changing while its name and type stay the same —
  the worst kind of break, and the one this rule exists to name.
- An error code's `slug` changing for an existing condition.
- An authentication or CSRF requirement being added to an endpoint that did not
  have one.
- The webhook signature scheme changing in a way an existing receiver would
  reject (see below).

---

## Specifically guaranteed

These are the things integrators build on, so they are called out rather than
left to inference:

- **The error envelope.** Every error is
  `{ "code": "FER-1201", "slug": "invalid_domain", "message": "…", "field": … }`.
  Branch on `slug`. An existing slug will not be reused for a different
  condition, and an existing condition will not silently change slug. New slugs
  appear in minor releases (`docs/api-errors.md` and `docs/api/errors.md` are
  generated from the enum).
- **The task protocol.** A long-running endpoint answers **202** with
  `{ "task_id", "task_url" }`, and the task's terminal states are
  `ok | failed | cancelled`. A client polling `/api/tasks/{id}` or streaming
  `/api/events` can rely on that shape.
- **Tenant scoping.** A resource outside the caller's tenant scope answers
  `not_found`, never `permission_denied` and never an empty success. That is a
  deliberate information-leak boundary, not an accident of implementation, and
  it will not change without a major bump.
- **Webhook deliveries.** The signature scheme, the header names and the
  envelope shape are documented in `docs/webhooks.md`. The `v1=` prefix on
  `X-Unihelm-Signature` exists so that a future scheme can be *added* beside the
  current one (`v1=…,v2=…`) in a minor release; removing `v1` would be major.
- **Operation names.** The dotted names in `docs/operations.md` are stable. They
  appear in audit rows, task records and the CLI, and renaming one would
  invalidate somebody's stored history.
- **The plugin protocol** has its own version, `api_version`, negotiated at
  install time and independent of this one (`docs/plugins.md`). A plugin is not
  an API client.

## Specifically *not* guaranteed

- **The exact wording of `message`.** It is for humans; `slug` is for programs.
- **Field ordering** in JSON objects, and whitespace.
- **The numeric ids** of rows across a restore or a migration.
- **Anything under `/api/dev/*`**, if such a namespace ever exists.
- **The `/healthz` body.** It is liveness for systemd and load balancers, not
  part of the product API. Its status code is stable; its body is not.
- **Undocumented behaviour.** If the OpenAPI document does not describe it, it
  is not part of the contract — including a field that happens to be present in
  a response but is absent from the schema. That is what makes the completeness
  test in `openapi.rs` worth having: a route that is not documented is a route
  nobody has promised anything about.

---

## How a change would be announced

1. The version in the document moves first, in the same change as the code.
2. A major bump is called out in `CHANGELOG` under a `Breaking` heading, with
   the migration written out — not "see the diff".
3. A removal is preceded by at least one minor release in which the endpoint or
   field is marked `deprecated: true` in the OpenAPI document, so a generated
   client warns before it breaks.

Unihelm is at `1.0.0`, which is a statement rather than a formality: from here,
breaking this API costs a major version and the announcement above.
