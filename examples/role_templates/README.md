# Example role-policy templates (pre-render)

These are role-policy *templates*: their build-time `{{build.X}}` tokens are
not yet bound. Run them through `mint render` to bake the deployment
constants and produce a ready-to-serve `roles_dir` — the sibling
[`demo_roles/`](../demo_roles) is what one looks like once rendered (its
bucket is already baked in).

```sh
mint render --in-dir examples/role_templates \
  --build bucket=my-bucket \
  --out-dir ./mint_roles
```

`{{build.bucket}}` is fixed here, once, at build/deploy. The request-time
tokens are passed through untouched and resolve per request when
`assume-role` renders the sealed template:

- `{{caveat.sub}}`     — issuer-stamped (the enrolled principal)
- `{{caveat.project}}` — attested (the caller proposes it; the attestation authority vouches it)
- `{{mint.expiry}}`    — mint-computed (the grant's expiry)

Point a config's `roles_dir` at the output directory, then `mint seal` it. A
`{{build.X}}` with no matching `--build` value fails the render and nothing
is written, so a half-bound template can never be sealed.
