# Design: self-service key rotation

Status: **proposed** (not yet implemented).

This document specifies an explicit operation for a coordinator to replace
its Ed25519 keypair while keeping its `sub` identity, authorized by key
continuity alone — no operator in the loop.

It is a companion to the enrollment lifecycle in `design-mint.md`
(elide repo) and to the change that made a different-key re-enroll an
error (a key change is no longer a side effect of `/v1/enroll`).

## Motivation

A coordinator's `sub` is an opaque, durable identity that may be
referenced in audit trails, policy, and external systems. Replacing the
keypair behind it — for routine hygiene or suspected key exposure short
of full compromise — should not churn that identity.

Today there are only two ways a `sub`'s key can change, and neither is a
clean rotation:

- **re-enroll under a different key** — now rejected. A live enrolled
  `sub` presented with a different `cnf` returns `StateError::Conflict`
  (opaque `401`). Key changes are no longer an implicit side effect of
  enrollment, and a party who merely knows a `sub` can no longer open a
  pending record against it.
- **`revoke` + fresh enroll** — operator-driven, correct for retirement
  or compromise (the `revoke` bumps the revocation epoch so the old key's
  credentials die for good), but it requires an operator and a fresh
  out-of-band approval, and it is overkill for a routine key swap by a
  coordinator that still controls its current key.

Rotation fills the gap: the holder of the current key swaps to a new key
in one self-service step.

## Trust model: key continuity

The enrolled record (`_mint/clients/enrolled/<sub>`) is already the
source of truth for the `sub ↔ key` binding. The operator established
that binding once, at enrollment, by confirming the original key's
fingerprint out of band.

Rotation extends that trust along a chain of key-signed swaps: **whoever
holds the currently-pinned key is the coordinator, and may move the
identity to a new key they also control.** Two proofs are required, or
the operation is exploitable:

1. **Old-key proof-of-possession** — only the current holder may
   initiate. This is the property that keeps rotation from being abusable
   by anyone who learns a `sub`.
2. **New-key proof-of-possession** — the identity cannot be bound to a
   key the requester does not control (confused-deputy defence).

Compromise of the current key is **not** made worse by rotation than it
already is: a thief of the current key can already mint credentials. The
marginal new harm is that they could also rotate to their own key and
lock the owner out. The remedy is unchanged — an operator `revoke` bumps
the epoch above the attacker's key. To make a hostile rotation
*detectable*, rotation emits an operator-visible audit line (see
[Audit](#audit)); that passive signal is the only operator touchpoint in
the self-service model.

## Why rotation needs its own entrypoint

Rotation cannot reuse a credential the client already holds. The
non-expiring primary minted at exchange (`issuance::mint_credential`)
bakes `op=assume-role` **and** a `role` caveat, and is minted per role.
Because `op` is a positively-required scalar, a held assume-role
credential cannot be attenuated to `op=rotate-key` — two `op` values
resolve to `Unsatisfiable` and fail closed. There is no op-agnostic
identity credential to carry a rotation request.

Rather than introduce one (a large change to the vending flow), rotation
is a small, self-contained endpoint that authenticates by **dual
signature against the pinned enrolled record**. This is a deliberate,
localized departure from the uniform "MAC against the keyring + `op` +
`aud` + PoP" shape of the other mint operations; it is justified because
the enrolled record is already the authority for the binding rotation
mutates.

## Wire protocol

New caveat partition value `op=rotate-key` (added to `caveat::op`).

New endpoint:

```
POST /v1/rotate-key
```

The request is macaroon-free:

```jsonc
{
  "sub":     "<claimed identity>",
  "ts":      <unix seconds, freshness>,
  "new_pub": "ed25519:<base64 new public key>",
  "old_pop": "<base64 Ed25519 signature over BIND, by the old key>",
  "new_pop": "<base64 Ed25519 signature over BIND, by the new key>"
}
```

The signed binding message is domain-separated and pins every value that
matters:

```
BIND = "mint-rotate-key-v1"
       ‖ aud
       ‖ sub
       ‖ old_pub
       ‖ new_pub
       ‖ ts
```

- The domain tag prevents `BIND` from colliding with any other signing
  context.
- `aud` binds the request to this mint instance (cross-mint replay
  defence), mirroring the `aud` caveat elsewhere.
- Including both `old_pub` and `new_pub` means neither signature can be
  lifted onto a different swap.
- `ts` gives freshness; combined with the epoch bump below, a captured
  request cannot be replayed (it would target a now-stale pin).

## Mint verification

At `/v1/rotate-key`, mint:

1. Loads `get_enrolled(sub)`. Absent (never enrolled, revoked, or a
   forged/corrupt record treated as absent) → `401`. Takes the pinned
   `old_pub` and current `epoch` from the record.
2. Rebuilds `BIND` from `(aud, sub, old_pub, new_pub, ts)`.
3. Checks `new_pub != old_pub` and that `ts` is within the freshness
   window.
4. Verifies `old_pop` against `old_pub` over `BIND`, and `new_pop`
   against `new_pub` over `BIND`.

Every failure is the opaque `401` used across the surface — no detail,
so causes cannot be distinguished. There is no `403`/`400` outcome:
rotation is all-or-nothing.

## State transition

`Store::rotate_key(sub, old_pub, new_pub)` performs a single atomic
overwrite of `_mint/clients/enrolled/<sub>`:

- `pubkey`           = `new_pub`
- `rev_epoch`        = `epoch + 1`  ← **the bump**
- `approved_by`      = `"self:rotation"`  (a distinct provenance marker, so
  an audit never mistakes a rotation for operator consent)
- `approved_at`      = now
- `fingerprint_shown`= `fingerprint(new_pub)`
- `mac`              = recomputed under the current keyring kid

The epoch bump is what retires the old key. Every old per-role credential
carries `(old cnf, old epoch)` and now fails `assume-role`'s
`a.pubkey == cnf && a.rev_epoch == cred_epoch` gate — both halves, in
fact. Bumping on every rotation also closes the "rotate back to a prior
key revives its old credentials" edge: a returned-to key gets a strictly
higher epoch, so its stale-epoch credentials stay dead.

No separate tombstone is written. The enrolled record itself now carries
the bumped epoch, and a later operator `revoke` reads and tombstones from
it, so revoke-resume correctness is preserved. The overwrite is a single
object-store PUT, so there is no torn intermediate state.

## Response and re-exchange

After the swap, the client's old per-role credentials are all dead, so
it must re-exchange under the new key. Rather than invent a new issuance
path, `/v1/rotate-key` returns a **fresh credential ticket**
(`op=enroll-exchange`, bound to `new_pub`) — exactly the artifact
`/v1/enroll` returns. The client then re-runs the existing `exchange`
flow once per role.

This reuses the entire exchange path. (Equivalently, because rotation has
already set `enrolled.pubkey = new_pub`, a plain `/v1/enroll` under the
new key would now hit the fast path and return a ticket; returning the
ticket directly just saves that round trip.)

## Client CLI

```
mint client rotate-key [--socket <path>]
```

1. Generates a new keypair under the client dir, kept alongside the
   current identity (the current private key is retained until success).
2. Builds `BIND`, signs it with both the old and new keys.
3. `POST /v1/rotate-key`.
4. On `200`: atomically swaps in the new private key and the returned
   credential ticket, discards the old key.
5. Re-runs `exchange` for each role the coordinator holds.

## Audit

A `rotate-key` audit line records `sub`, the old→new fingerprint
transition, and the new epoch:

```
rotate-key sub=<sub> old_fp=<…> new_fp=<…> epoch=<N>
```

Because rotation is self-service, this log is the operator's visibility
into key changes — and the means by which an unexpected (hostile)
rotation is noticed after the fact.

## Surface-area summary

**New:**

- `op=rotate-key` constant in `caveat::op`.
- `/v1/rotate-key` handler in `http.rs`.
- A `BIND` construction + dual-signature verification helper (a new
  signing construction distinct from the macaroon-tail PoP).
- `Store::rotate_key`.
- A `rotate-key` audit outcome.
- `mint client rotate-key` subcommand.

**Reused unchanged:**

- The enrolled record and its MAC.
- The revocation-epoch machinery.
- Credential-ticket issuance (`issuance::mint_invite` /
  `mint_credential_ticket` path) and the entire `exchange` flow.
- `assume-role`, the template seal, and the macaroon wire format.

## Alternatives considered

- **Operator-approved rotation.** Rotation creates a pending-rotation
  record; an operator confirms the new fingerprint out of band before the
  swap, exactly like enrollment. Preserves the operator's continuous
  ground-truth on which key is current, at the cost of a manual approval
  per rotation. Rejected in favour of key continuity: old-key PoP already
  restricts initiation to the legitimate holder, and routine key hygiene
  should not require operator toil. (Compromise — where the operator
  *should* intervene — is still served by `revoke`.)

- **A reusable op-agnostic identity credential.** Mint a bare
  identity credential at exchange (no `op`, no `role`) that the client
  attenuates per use to `op=assume-role` or `op=rotate-key`. This would
  keep rotation on the uniform macaroon+PoP auth path, but it is a
  substantial redesign of the per-role vending flow (role is baked at
  exchange today). Deferred; the dual-signature endpoint is far smaller.

- **Overloading `/v1/enroll`.** Accept a different-key enroll for a live
  `sub` when accompanied by old-key PoP, and auto-approve it. Rejected:
  it re-muddies the boundary that the revoke-first change deliberately
  drew — a key change should be an explicit, separately-named operation,
  not a conditional branch inside enroll.
