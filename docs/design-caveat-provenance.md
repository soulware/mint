# Design: caveat provenance, and the removal of `[env]`

Status: **landed**. Holder-provenance scaffolding (PR #23), exchange baking
(PR #24), and the `[env]` removal (PR #26).

This document specifies a single, uniform model for how every value a
policy template substitutes enters a credential. It replaces the current
split between server-config `{{env.X}}`, holder-narrowed `{{caveat.X}}`,
and discharge-vouched attested values with **one mechanism — bake a value
into the fresh-from-root chain — fed by a per-caveat declared *source*.**
The `[env]` config table and the `{{env.X}}` render namespace are removed.

It is a companion to the enrollment/vending lifecycle in `design-mint.md`
(elide repo) and to `design-mint-template-seal.md`. The exchange-request
body changes shape and role templates must be rewritten, so this is a
**breaking change for the elide side** (elide authors the values mint used
to hold in `[env]`). mint can land it standalone, though: the in-tree
reference client moves with the change, and elide adapts to the new
exchange contract on its own schedule — there is no lockstep requirement.

## Motivation

`[env]` conflates two unrelated jobs, and both are smells:

1. **Per-credential scope dressed as server config.** In the demo,
   `[env]` holds `bucket` and `prefix` — exactly the resource-scoping
   values that distinguish one workload from another. Putting them in
   server config means every credential a mint instance vends carries the
   same scope, with no attenuation story, and two replicas with drifted
   `[env]` render different policies for the same credential.
2. **Source-of-truth on the wrong side.** The bucket is *elide's* fact,
   not the mint operator's. With `[env]`, mint must be told it out of
   band, and there are now two places (mint's TOML and elide's environment
   config) that have to agree, with nothing keeping them in sync. Sealing
   `[env]` pins it against *forgery* but does nothing about *drift* — the
   value still originates in hand-authored mint config.

The fix is not to make these per-credential caveats for their own sake
(they may not even vary per credential — a dedicated mint runs one bucket
per deployment). The fix is to recognize that **how a value is allowed to
enter a credential is a property of the role, and the value itself travels
with the credential, authored by whoever owns it.** Once that is explicit,
`{{env.X}}` has no remaining job: a per-deployment scope value becomes a
caveat elide supplies, and a genuine deployment constant becomes a literal
written directly into the policy template.

## The model: three provenances, one baking step

Every name a role's template substitutes (`{{caveat.X}}`) is assigned
exactly one **source**:

| Source     | Who authors the value          | Where it arrives                    | What mint does            |
|------------|--------------------------------|-------------------------------------|---------------------------|
| `issuer`   | mint, from its own authority   | mint computes it                    | validate, then **stamp**  |
| `holder`   | the client (elide/coord)       | the PoP-signed exchange body        | **copy** verbatim         |
| `attested` | an external attestation authority | a discharge macaroon (TPC)       | verify, then bake         |

The reserved issuer names are the existing control caveats — `sub`,
`role`, `epoch` (see `caveat::name::RESERVED`). `role` is the canonical
issuer caveat: the holder *requests* it in the body, but mint validates it
against the configured roles and stamps it **from root** — it is not
trusted from the holder, it is authorized and re-issued.

All three land in the issued primary as **ordinary MAC'd caveats**,
indistinguishable downstream and resolved through the single
`{{caveat.X}}` namespace. This finishes the collapse the render layer
already started: there is no `{{attested.X}}` namespace (a stale one is
already rejected at seal as a malformed token); attested values have
rendered as `{{caveat.X}}` since they began baking at `exchange-finalize`.
This change extends that same "bake an arrived value" treatment to
holder-supplied values, and makes the source an explicit, sealed property
of the role rather than an implicit consequence of which endpoint stamped
the value.

### "Stamp" is two things — keep them distinct

Mechanically, baking is identical for all sources: MAC the `(name, value)`
into the fresh chain. But the *trust* differs and must not be flattened:

- An `issuer` caveat (`role`) is **vouched** — mint asserts it is a real,
  authorized role.
- A `holder` caveat (`bucket`) is **carried** — mint MACs the holder's
  assertion so it is tamper-proof *thereafter*, but mint makes no claim
  that it is correct. The backstop is the IAM account boundary (below),
  not a mint vouch.
- An `attested` caveat (`volume`) is **vouched by a third party** — an
  independent decision point (the attestation authority), relayed via an
  `r`-bound discharge under `K_M-B`, which the holder cannot forge.

The sealed per-caveat source is what keeps this explicit. "mint stamps
them all" is true of the *mechanism* and false of the *trust*.

## Render namespaces after this change

`template::render_policy` drops its `env` argument and the `env` arm of
`classify_token`. The accepted namespaces become exactly two:

- `{{caveat.X}}` — MAC-verified, credential-authored (any of the three
  sources above).
- `{{mint.X}}` — mint-computed (today only `{{mint.expiry}}`).

Nothing in the render path is server-config-authored.

## Config schema

A role declares its full caveat manifest and partitions it by source.
`holder` is new; `attested` already exists.

```toml
[role.template]
# The full manifest of {{caveat.X}} the template binds, whatever the source.
caveat = ["sub", "bucket", "prefix", "volume"]
# Subset supplied in the exchange body and copied verbatim.
holder = ["bucket", "prefix"]

[role.attestation]
# Subset vouched by the attestation authority's discharge.
attested = ["volume"]
intermediate_ttl_seconds = 0
```

The remainder (`caveat − holder − attested`) must be reserved issuer
names — here `{sub}`. Validation at config load (in `config.rs`, alongside
the existing `AttestedNotInCaveat` / `ReservedAttestedKey` checks):

- `holder ⊆ caveat` and `attested ⊆ caveat` (new `HolderNotInCaveat`
  mirrors the attested check).
- `holder ∩ attested = ∅` — a value is either self-asserted or vouched,
  never both (new `SourceConflict`).
- `holder ∩ RESERVED = ∅` — a client cannot self-assert `sub`/`role`/
  `epoch` (reuses the reserved-key guard).
- every non-`holder`, non-`attested` name in `caveat` is a reserved issuer
  name — no caveat is left with an undeclared source.

A gate-only attested role (`attested = []`, a discharge still required but
no value baked) is unchanged. A role with no `holder` and no `attestation`
is a pure issuer-caveat role, exactly as today.

## Wire protocol

`ExchangeBody` (the PoP-signed body at `POST /v1/enroll-exchange`) grows
from `{ role }` to carry the holder values:

```jsonc
{
  "role": "<requested role>",
  "ts":   <unix seconds, freshness>,        // already present, for PoP
  "caveats": { "bucket": "...", "prefix": "..." }
}
```

No new transport channel is introduced. The body is already covered by the
PoP — `Ed25519(tail ‖ BLAKE3(raw-body))` under the holder's `cnf` key — so
the holder values inherit integrity, holder-binding, and freshness for
free. An on-the-wire attacker cannot modify a value and re-sign (no holder
key); a verbatim replay reproduces a credential bound to the legitimate
holder's `cnf` and is unusable. `role` stays exactly where it is — it is a
*selector* (it picks the template/contract mint must interpret now), while
the `caveats` map carries *fillers* (values mint copies through).

`attested` values do **not** travel in the body — they arrive, as today,
via the discharge macaroon presented at `POST /v1/exchange-finalize`.

## Issuance and baking

`issuance::mint_credential`'s `baked_attested: &[(String, String)]`
parameter generalizes to `baked: &[(String, String)]` — by the time a
value is baked it is just a MAC'd caveat; its source mattered only at the
point it was *collected*, which is config-time, not issuance-time.

At `POST /v1/enroll-exchange`, after authenticating the ticket and PoP and
validating `role`, mint resolves the role's sealed `holder` set against the
body's `caveats` map:

1. For each name in `holder`: take its value from `body.caveats`. **Absent
   → fail closed** (a `400`/role-denial, not a primary doomed to fail at
   assume-role). Names in `body.caveats` **not** in the `holder` set are
   ignored — the sealed set is the allow-list, exactly as the sealed
   `caveat` set is at `assume-role`.
2. **Non-attested role:** call `mint_credential` with `baked` = the
   collected holder values (today this list is empty at this call site).
3. **Attested role:** call `mint_intermediate`, baking the holder values
   into the intermediate so they ride to finalize, alongside the
   undischarged attested TPC. At `POST /v1/exchange-finalize`, mint
   re-mints the primary from root, reading the holder values back off the
   presented intermediate via `EffectiveCaveats` and the attested values
   off the verified discharge, and bakes both. Both land in the primary.

The append-a-contradictory-copy defence carries over unchanged: a holder
value read via `EffectiveCaveats` that has ≥2 disagreeing occurrences
resolves `Unsatisfiable` and fails closed rather than substituting a
forgery.

## Seal

`seal::SealedRole` gains a `holder: Vec<String>` field beside the existing
`caveat` and `attested`. Sealing the source partition is **load-bearing**,
not cosmetic: if local config could quietly reclassify an `attested`
(third-party-vouched) name as `holder` (self-asserted), that is a
provenance-downgrade attack — a bucket-credential holder could drop the
authority from the loop. Pinning the partition under the keyring closes
it, the same way the seal already pins the `caveat` contract and the
policy-template hash.

The seal authoring cross-check in `config.rs` extends accordingly: the
template's actual `{{caveat.X}}` tokens must still match the declared
`caveat` set exactly (`CaveatContractMismatch`), and `holder`/`attested`
must be declared subsets of it.

## `assume-role` is unchanged

The request-path enforcement needs no new logic. `holder` and `attested`
names are members of `caveat`, so the existing presence check —
"every sealed `caveat` name must resolve to a single `Value` in the
MAC-verified chain, else `400`" — already covers them. A holder cannot
override a baked value: appending a contradictory copy makes the name
`Unsatisfiable` and fails the presence check closed. There is no separate
discharge context at `assume-role`; everything was baked at exchange.

## Trust model: what makes a self-asserted `holder` value safe

A `holder` value is, by construction, **not** vouched by anyone — mint
copies the client's claim. In a dedicated-per-deployment topology (one
mint instance per environment) this is safe because **mint's IAM admin
credential is scoped to that environment's account/bucket.** A client that
asserts `bucket=production` against the staging mint gets a credential the
staging admin credential cannot honour — the IAM boundary refuses to mint
keys into an account it does not control. The worst a client can do is
scope itself to a bucket it cannot reach: self-harm, not escalation.

This invariant is the load-bearing assumption and must be written down:

> **`holder`-sourced scope is contained by the deployment's IAM account
> boundary.** The macaroon authenticates *who* asked and makes the value
> tamper-proof; it does not bound *which* resources the value names. That
> bound is the IAM admin credential's own scope.

The moment one mint's admin credential spans multiple accounts/buckets,
that backstop is gone and any scope-selecting value must move from
`holder` to `attested` (so an authority, not the holder, chooses). That is
a per-role config flip — `holder = [...]` → `attested = [...]` — with no
change to the baking machinery, which is the point of the unified model.

## Migration

- **Remove `[env]`**: delete the `env` table from config, the
  `Config.env` field, `env_scalar_to_string`, the `NonScalarEnv` error,
  and `env` from the sealed served surface.
- **Reclassify each former `[env]` key** as either a `holder` caveat (a
  scope value elide now supplies in the exchange body) or a literal
  written directly into the policy-template JSON (a true deployment
  constant).
- **Rewrite role templates**: every `{{env.X}}` becomes `{{caveat.X}}`
  (with `X` declared in `holder`/`attested`) or an inlined literal. A
  leftover `{{env.X}}` now fails seal as a malformed-token, the same way a
  stale `{{attested.X}}` already does — a loud, fail-closed migration.
- **elide side** (adapts later, not in lockstep): elide's environment
  manifest becomes the single source of truth for the former `[env]`
  values, sent in the `exchange` body. The in-tree reference client ships
  the new body shape with this change — `mint client exchange` gains
  `--caveat N=V`, mirroring the existing `assume-role --caveat` — so mint
  is testable end-to-end without elide; elide moves to the new contract
  when it picks up the release.
- **Docs**: drop the stale `{{attested.X}}` entry from the module map in
  `CLAUDE.md`/README and replace the four-namespace description with the
  two-namespace one.

## Surface-area summary

**New:**

- `holder` field on `[role.template]`, on the resolved `Role`, and on
  `seal::SealedRole`.
- Config-load validation: `HolderNotInCaveat`, `SourceConflict`, reserved
  guard for `holder`.
- A `caveats: BTreeMap<String, String>` field on `ExchangeBody`, and the
  enroll-exchange handler step that resolves the sealed `holder` set
  against it (allow-list + fail-closed-on-missing).
- `mint client exchange --caveat N=V`.

**Changed:**

- `issuance::mint_credential` / `mint_intermediate`: `baked_attested` →
  generic `baked`.
- `template::render_policy` / `classify_token`: drop the `env` namespace
  and argument.
- Seal authoring cross-check: validate `holder`/`attested ⊆ caveat`.

**Removed:**

- `[env]` table, `Config.env`, `env_scalar_to_string`, `NonScalarEnv`,
  `env` on the served surface, the `{{env.X}}` render namespace.

**Reused unchanged:**

- The whole `assume-role` request path (sealed `caveat` presence check
  already covers `holder`/`attested` names).
- The attestation two-step, `K_M-B`, the discharge/TPC machinery.
- `EffectiveCaveats` and the append-a-contradictory-copy defence.
- The PoP construction, the macaroon wire format, the keyring, and the
  template seal's hash-pinning.

## Alternatives considered

- **Force every template caveat through attestation.** The original
  instinct ("all caveats attested; the authority may pass-through,
  rewrite, or add"). Rejected: it conflates *attenuation* with
  *attestation*. Narrowing/issuer and self-asserted values do not need an
  external authority, and routing them through one adds an availability
  dependency and a per-use round trip (e.g. for a `0`-TTL intermediate
  finalized per volume) for no security gain — the echo authority would
  rubber-stamp them. The three-source model keeps attestation for exactly
  the values that want an independent decision, and lets a role adopt it
  per-caveat by flipping `holder` → `attested`.

- **Carry `holder` values as caveats attenuated onto the presented
  ticket** (rather than in the body). Considered, because "values live as
  caveats" is appealing and a ticket caveat gets the contradiction defence
  for free. Rejected: it buys nothing the PoP-signed body does not already
  give (the body is integrity-bound and holder-bound), it invents a third
  collection channel beside the body and the discharge, and the
  append-only + contradiction semantics would pin the otherwise
  role-agnostic, multi-use enrollment ticket to a single shape. The caveat
  machinery earns its keep in the *issued primary* (at `assume-role`), not
  in the request.

- **Pin scope at enrollment** (bake `bucket`/`role` into the ticket mint
  issues, per-`(sub, role)` approval). Gives a smaller blast radius under
  *full* key compromise (a single-shape ticket mints fewer credentials in
  its window). Rejected as the default: it forfeits the deliberate
  one-approval-many-roles enrollment flow, and the threat it addresses
  (holder key + ticket both stolen) is narrow. Left available as a
  per-deployment posture, not the model.

- **Keep `[env]`, fix only the source-of-truth** (generate mint's `[env]`
  from elide's manifest at deploy time). Solves drift without a runtime
  change. Rejected in favour of the caveat path because it keeps two
  mechanisms for "a value the template substitutes" where one suffices,
  and it leaves the seal pinning a *value* it has no business owning; the
  unified model lets the seal pin only the *contract* (which names, which
  source) while the value rides the credential.
