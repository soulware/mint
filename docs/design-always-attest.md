# Design: always-attest — retiring `holder`, collapsing to two provenances

Status: **proposed** (not yet implemented). Revises the three-provenance
model in `design-caveat-provenance.md` (landed): `holder` is removed as a
distinct source.

This note collapses the caveat-provenance model from three sources to two.
Today a `{{caveat.X}}` value is `issuer`-stamped, `holder`-supplied, or
`attested`. This note removes `holder` as a separate mechanism by observing
that **holder-supplied is just attestation against a permissive authority**,
and routes *every* client-proposed value through the attestation authority.
A caveat is then one of exactly two things: mint-controlled (`issuer`) or
authority-vouched (`attested`). It is a breaking change for elide; mint can
land it standalone, its in-tree reference client moving in step.

## Motivation

The three-provenance model makes the operator answer a question for every
caveat: is `bucket` holder-supplied or attested? In a role that already runs
attestation, that question has no principled answer — `bucket` could be
either, and the config's only job is to pick one. Worse, the two choices are
not security-symmetric: `holder` means the **client** decides the value
(bounded only by the IAM account); `attested` means an **authority** does.
Defaulting or mis-flagging silently moves control of a value between the
client and the authority — a fail-open footgun for the exact gate
attestation exists to provide.

The split also costs a whole config surface — the `caveat`/`holder`/
`attested` lists and their subset/disjointness fences — and a second,
parallel baking path: holder values baked at `enroll-exchange`, attested
values baked at `exchange-finalize`.

The observation that removes all of it: **`holder` is `attested` with an
authority that approves whatever is asked.** The demo attestation authority
is exactly that — echo-only. So a holder caveat is not a different *kind* of
value; it is the same "client proposes, authority vouches" value against a
permissive verdict. Make that uniform and the per-caveat question
disappears: a non-issuer caveat is *always* attested.

## The model: two provenances

| Source     | Who decides the value                     | What mint does                     |
|------------|-------------------------------------------|------------------------------------|
| `issuer`   | mint, from its own authority              | validate, then **stamp** from root |
| `attested` | the client proposes, an authority vouches | verify the discharge, then **bake**|

`issuer` is exactly the reserved control names (`caveat::name::RESERVED`:
`sub`, `role`, `epoch`, …). `attested` is **everything else** — every
non-reserved `{{caveat.X}}` the template binds.

There is nothing to declare per caveat. A role's provenance is fully derived
from its policy template:

- a `{{caveat.X}}` where `X ∈ RESERVED` → issuer-stamped;
- a `{{caveat.X}}` where `X ∉ RESERVED` → attested.

A role with ≥1 non-reserved caveat is an **attested role**: its credential
carries a third-party caveat, and the full set of non-reserved values is
posted to the authority and baked from the discharge. A role with only
reserved caveats (sub-scoped) is an **issuer-only role**: one-step exchange,
no TPC, no authority.

### Why this is fail-closed

mint never bakes a client-proposed value without an authority's discharge.
The only values mint stamps on its own authority are the reserved identity
caveats. Every value the *client* influences passes through the authority
first. The "client controls it, unvouched" path (`holder` baked straight
from the exchange body) is gone — so a mis-configured role can no longer
silently hand value-control to the client. The "why is `bucket` not attested
here?" question cannot be asked, because `bucket` always is.

## Config schema

Provenance is derived, so the role drops its entire caveat-declaration
surface. `[role.template]` (the `caveat`/`holder` lists) and the `attested`
list under `[role.attestation]` are removed.

Before (today):

```toml
[role.template]
caveat = ["bucket", "project", "sub"]
holder = ["bucket"]
[role.attestation]
attested = ["project"]
intermediate_ttl_seconds = 0
```

After:

```toml
[[role]]
name = "demo-attested"
ttl_seconds = 300
# Attested roles exchange via a durable (no-`exp`) intermediate the holder
# finalizes per-use — e.g. a coordinator minting a credential per volume.
# policy_file defaults to demo-attested.json — bucket and project are attested
# (non-reserved); sub is issuer (reserved).
```

There is no `[role.attestation]` subtable any more, and no per-role TTL knobs
beyond a single `ttl_seconds`. `mode` and the `attested` list were already
derived; the credential's lifetime is one `ttl_seconds` (the grant is that,
clamped to the macaroon's own `exp` — a holder attenuates `exp` to ask for
less), and the intermediate is always durable, so there is no
`intermediate_ttl_seconds`. A role is now just its `name`, a single
`ttl_seconds`, and a policy file.

Validation at config load:

- a role that binds ≥1 non-reserved caveat is **attested**: it requires a
  configured `attestation.location`. Missing → **fail closed at load** (via
  today's `AttestationWithoutLocation`, now reachable whenever the template
  carries a non-reserved caveat).
- the `caveat`/`holder`/`attested`/source-conflict cross-checks are deleted:
  there is nothing left to reconcile, because the manifest *is* the template
  (`template::template_surface`) and the partition is `RESERVED` membership.

**Gate-only roles are removed.** There is no longer a way to require an
attestation verdict without baking a value — attestation exists to vouch
values, so a role with no non-reserved caveat has nothing to attest and runs
issuer-only. Dropping this case removes the one role that needed an explicit
attestation marker, which is what lets the subtable disappear entirely.

## Wire protocol

`ExchangeBody` at `POST /v1/enroll-exchange` loses its `caveats` map — there
are no holder values to carry — returning to `{ role, ts }`. For a
caveat-bearing role, `enroll-exchange` always returns the
`op=exchange-finalize` intermediate (the TPC); its one-step "bake holder
values" branch is gone.

Client-proposed values now travel where attested values already do: in the
request to the attestation authority. `attest::AttestRequest` carries the
full non-reserved set (was the `attested` subset):

```jsonc
{ "cid": "...", "caveats": { "bucket": "...", "project": "..." } }
```

The authority returns a discharge carrying the vouched `(name, value)` set,
and `POST /v1/exchange-finalize` bakes them all into the primary from root.
The CID is unchanged — it still seals `(sub, org, role)` under `K_M-B`; the
authority keys its verdict off `(sub, role)` and the proposed set.

Issuer-only roles are unchanged from today's non-attested path minus holder
baking: one-step `enroll-exchange`, mint stamps the reserved caveats (`sub`)
from root, no TPC.

## Issuance and baking

`issuance::mint_intermediate` / `mint_credential` are unchanged — they
already take a uniform `baked: &[BakedCaveat]`. What changes is *where the
set is collected*: entirely at finalize, from the discharge, for every
attested value. The `enroll-exchange` holder-collection step (and the sealed
`holder` allow-list it consulted) is removed. The append-a-contradictory-copy
defence via `EffectiveCaveats` carries over unchanged.

## Render

Unchanged. The two render namespaces — `{{caveat.X}}` (MAC-verified) and
`{{mint.X}}` (mint-computed) — stay; baked attested values resolve through
`{{caveat.X}}` exactly as today. The provenance *vocabulary* in the docs
drops to two; "holder-supplied" is retired, or described as the
permissive-authority case.

## Client CLI

`mint client exchange` collapses `--caveat` (holder) and `--attest`
(attested) into a single repeatable value flag — there is one kind of
client-proposed value now, and it always goes to the authority. An
issuer-only role takes no value flags.

## Demo mode: a co-located authority, like auth

In production the attestation authority is a separate party that holds `K_M-B`
and decides verdicts mint cannot. The demo models that **exactly as the demo
auth role already does**: a co-located authority living *in mint's process*,
holding an auto-generated `K_M-B`, served on its own socket (`attest.sock`)
alongside `auth.sock`. The client reaches it the way it reaches the auth
discharge plane — by *calling* it with a login session — and holds no `K_M-*`
key itself. The two co-located demo authorities share that one login session as
their gate, which is why `[attestation.demo]` requires `[auth.demo]`
(`config.rs`, `DemoAttestationWithoutDemoAuth`).

An earlier draft proposed collapsing this into a "do-nothing" in-process
discharge — dropping `K_M-B` and `attest.sock` and having mint (recovering `r`
from the VID) or the client mint the discharge directly, on Fly's aside that an
issuer "could make a 'do-nothing' 3P caveat … and mint a discharge Macaroon at
the same time." That is **not** the design. Two facts rule it out:

1. **A client must never hold a `K_M-*` key.** The codebase keeps this
   invariant throughout: `K_M-A` is server-side only — mint stamps CIDs with
   it, the auth service decrypts them, and the client gets discharges by
   *calling* that service over a session-gated socket, holding a session and
   never the key (`client.rs` / `session.rs` name no `K_M-*`). Letting a demo
   client read `K_M-B` to self-discharge would be the first crack in that
   invariant, cut for a demo affordance. So the discharge stays with a
   co-located authority that holds `K_M-B`; the client calls it.
2. **mint stays a pure verifier.** mint issues the third-party caveat and
   verifies the discharge at `exchange-finalize`; it does not mint discharges.
   Folding a do-nothing discharge into mint's request path would bend a
   production endpoint's contract to a demo shortcut. Keeping the authority on
   `attest.sock` leaves `enroll-exchange` / `exchange-finalize` byte-identical
   between demo and production.

Fly's "do-nothing" line is a casual one ("just for funsies") and does not
anticipate late-bound attested values proposed per-finalize. The load-bearing
idea we keep from it is only that *the verifier cannot distinguish a co-located
authority from a remote one* — which holds here: the demo authority is a
faithful scaled-down coord-B (same TPC, same `CID`-under-`K_M-B`, same discharge
round-trip over a socket), differing only in that the party answering
`attest.sock` is in mint's process rather than on a separate host. Production's
"fetch a discharge over a transport" path is therefore exercised by the default
demo itself, not a special-cased test.

## Consequences

This is a deliberate trade of flexibility for a uniform, fail-closed model.
The costs are real:

1. **The attestation authority is mandatory** for any role that scopes by a
   client-chosen value, and a hard availability dependency for that role's
   exchange path. A deployment with no authority can offer only issuer-only
   (sub-scoped) roles. Today a holder-only role needs no authority; that
   capability is removed.
2. **Every client value costs a discharge round-trip.** A self-scoping
   `bucket` an echo authority rubber-stamps still pays the two-step exchange
   + discharge. The durable intermediate softens this — a coordinator
   finalizes per-use without re-enrolling.
3. **Value policy moves from mint config into the authority.** You can no
   longer read "bucket is client-controlled" from mint's TOML; the authority
   owns the per-name verdict. This is arguably correct — the authority is the
   trust point — but it relocates the decision.
4. **The demo changes shape.** The two roles (holder `demo`, attested
   `demo-attested`) collapse. A cleaner demo: one issuer-only role
   (sub-scoped, no authority) and one attested role whose value the co-located
   attestation authority vouches (on `attest.sock`, see *Demo mode* above) —
   showcasing the two real provenances.

## Decisions

1. **No-authority caveat role → load error.** Settled: yes, fail closed — a
   caveat-bearing role with no `attestation.location` is rejected at load.
2. **A single per-role `ttl_seconds`; the intermediate is always durable.**
   The credential's lifetime collapses from `min`/`max`/`default_ttl_seconds`
   to one required `ttl_seconds`, with no request-body override — a holder
   attenuates its macaroon's `exp` to ask for less. The attested intermediate
   carries no `exp` and is finalized per-use, so there is no
   `intermediate_ttl_seconds` knob.
3. **Gate-only roles are removed.** Attestation exists to vouch values; a role
   with no non-reserved caveat has nothing to attest and runs issuer-only.
   Removing this case is what lets the `[role.attestation]` subtable disappear.

## How it lands

mint lands this standalone; the in-tree reference client moves with it, and
elide adapts its exchange/attest contract on its own schedule (no lockstep).
A sensible sequence:

1. **Authority always in the loop.** Move value collection from
   `enroll-exchange` to the attest request + finalize; `enroll-exchange`
   always issues an intermediate for a caveat-bearing role. `ExchangeBody`
   drops `caveats`; `AttestRequest` carries the full set. The reference
   client merges `--caveat`/`--attest` into one value flag.
2. **Derive provenance from the template.** Delete `[role.template]` and the
   `holder`/`attested` declarations; derive issuer/attested from `RESERVED`
   membership over the template tokens. Remove the `[role.attestation]`
   subtable and gate-only roles. Update the seal surface (drop `holder`).
3. **Collapse the TTL surface.** Replace `min`/`max`/`default_ttl_seconds` and
   the request-body override with a single per-role `ttl_seconds`; drop
   `intermediate_ttl_seconds` and make the attested intermediate always
   durable. The seal pins `ttl_seconds`; `authorize` grants it clamped to the
   presented macaroon's `exp`.
4. **Demo, config, and docs.** Keep the colocated attestation authority on
   `attest.sock` (it mirrors `auth.sock`, holds `K_M-B`, and is gated by the
   demo login session); rewrite the demo roles (issuer-only + attested), the
   seal/validation, README, and CLAUDE.md to the two-provenance vocabulary.
