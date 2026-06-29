# Enrollment kinds

An **enrollment kind** bounds the set of roles an enrolled client may
exchange. The enrollee declares a kind at `/v1/enroll`; mint maps the
kind to a role set, records it on the enrolled registry entry under that
entry's MAC, and refuses any role outside the set at
`/v1/enroll-exchange`. This makes a scoped enrollment — for example a
read-only attestation authority that should only ever hold a read role —
**mint-enforced** rather than a property of the client behaving well.

This is mint's side of the cross-repo contract in
`soulware/elide`'s `docs/attestation-readonly-enrollment-spec.md`.

## The mapping is config-owned, the kind is client-declared

Kinds live in `[enroll.kinds]` in `mint.toml`, each mapping a kind name
to the roles it grants:

```toml
[enroll.kinds]
coordinator = ["coord-ro", "coord-rw", "volume-rw", "volume-ro"]
attestation = ["coord-ro"]
```

The enrollee **declares** a kind; the mint operator **owns** what each
kind grants. So an enrollee selects a privilege class — it can never
request an arbitrary role subset, and adding a kind never means trusting
a client-supplied role list. mint coins no kind names of its own: the
name space is the deployment's, and the role names are the deployment's
configured `[[role]]`s.

Validation at config load:

- `[enroll.kinds]` is **required and non-empty** — a mint with none can
  enroll no one, so it fails closed at startup rather than at the first
  `/v1/enroll`.
- each kind grants at least one role, and
- every granted role is a configured `[[role]]`.

## The flow

1. **`POST /v1/enroll`** carries `kind` in the PoP-signed body
   (`{ts, kind}`), so the declared kind is bound to the enrollee. An
   absent or unrecognised kind is a `400` — never defaulted to a wider
   grant. The kind is written onto the pending record.
2. **`mint enroll list` / `mint enroll approve <sub>`** show the kind
   alongside the `cnf` fingerprint. The operator already matches the
   fingerprint out of band; ratifying the privilege class at that same
   checkpoint is the trust act. `approve` writes the kind onto the
   long-lived enrolled record, **covered by the record body MAC** — a
   bucket-level writer cannot widen the grant by swapping it.
3. **`POST /v1/enroll-exchange`** resolves the enrolled record's kind to
   its role set and refuses any `role` outside it with **`422`**.

## Why `422`

Every auth failure on the mint surface collapses to an opaque `401`, and
a not-yet-approved enrollment is the one awaited `403`. The exchange
client treats `403` as *awaiting approval* and `401` as *ticket expired*,
and polls on `403`. A role-outside-grant denial is neither: it is a
durable refusal that must fail loudly, so it uses `422` — outside the
`{200, 401, 403}` the client interprets, which surfaces it as a hard
error instead of an infinite poll. A legitimate client, only ever asking
for a granted role, never sees it; `422` is the structural backstop
against a buggy or compromised client reaching past its grant.

## Scope

This is an enrollment-grant mechanism only. The attested third-party
caveat `cid` seal, the discharge MAC, `K_M-B`, and the macaroon domain
are unchanged — a kind constrains which roles an enrollment exchanges,
nothing about how a credential is later discharged or rendered.
