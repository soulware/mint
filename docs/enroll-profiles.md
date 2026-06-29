# Enrollment profiles

An **enrollment profile** bounds the set of roles an enrolled client may
exchange. The enrollee declares a profile at `/v1/enroll`; mint maps the
profile to a role set, records it on the enrolled registry entry under that
entry's MAC, and refuses any role outside the set at
`/v1/enroll-exchange`. This makes a scoped enrollment — for example a
read-only attestation authority that should only ever hold a read role —
**mint-enforced** rather than a property of the client behaving well.

This is mint's side of the cross-repo contract in
`soulware/elide`'s `docs/attestation-readonly-enrollment-spec.md`.

## The mapping is config-owned, the profile is client-declared

Profiles are declared in `mint.toml` as top-level `[[profile]]` entries — a
sibling catalog to `[[role]]` — each a `name` and the `roles` it grants:

```toml
[[profile]]
name = "coordinator"
roles = ["coord-ro", "coord-rw", "volume-rw", "volume-ro"]

[[profile]]
name = "attestation"
roles = ["coord-ro"]
```

The enrollee **declares** a profile; the mint operator **owns** what each
profile grants. So an enrollee selects a privilege class — it can never
request an arbitrary role subset, and adding a profile never means trusting
a client-supplied role list. mint coins no profile names of its own: the
name space is the deployment's, and the role names are the deployment's
configured `[[role]]`s.

Validation at config load:

- at least one `[[profile]]` is **required** — a mint with none can enroll
  no one, so it fails closed at startup rather than at the first
  `/v1/enroll`.
- each profile name is unique and grants at least one role, and
- every granted role is a configured `[[role]]`.

## The flow

1. **`POST /v1/enroll`** carries `profile` in the PoP-signed body
   (`{ts, profile}`), so the declared profile is bound to the enrollee. An
   absent or unrecognised profile is a `400` — never defaulted to a wider
   grant. The profile is written onto the pending record.
2. **`mint enroll list` / `mint enroll approve <sub>`** show the profile
   alongside the `cnf` fingerprint. The operator already matches the
   fingerprint out of band; ratifying the privilege class at that same
   checkpoint is the trust act. `approve` writes the profile onto the
   long-lived enrolled record, **covered by the record body MAC** — a
   bucket-level writer cannot widen the grant by swapping it.
3. **`POST /v1/enroll-exchange`** resolves the enrolled record's profile to
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
are unchanged — a profile constrains which roles an enrollment exchanges,
nothing about how a credential is later discharged or rendered.
