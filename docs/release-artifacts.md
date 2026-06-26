# Release artifacts: building, publishing, and consuming the mint binary

Status: **operational**. The release workflow (`.github/workflows/release.yml`) landed
in PR #43; `v0.1.0` is the first published release.

`mint` is a generic credential broker. Role templates and the `mint render` pass that
bakes their deployment constants are **deployment-specific**, so the artifact boundary is
the **binary**, not a full container image: a deployment pulls the stock `mint` binary and
supplies its own templates + config. This note documents what mint publishes, how to cut a
release, and how a deployment consumes the artifact (worked example: elide's Fly image).

## What mint publishes

On a `v*` tag push, `.github/workflows/release.yml` builds `mint` for
`x86_64-unknown-linux-gnu` on `ubuntu-24.04` and attaches two assets to a GitHub Release:

```
https://github.com/soulware/mint/releases/download/<tag>/mint-x86_64-unknown-linux-gnu
https://github.com/soulware/mint/releases/download/<tag>/mint-x86_64-unknown-linux-gnu.sha256
```

- **glibc x86-64 ELF**, dynamically linked against glibc 2.39 (the ubuntu-24.04 builder's).
  It runs on any glibc base of that vintage or newer — `ubuntu:24.04` is the matched
  runtime. A musl/alpine base would need a separate musl build (not published today).
- The asset name carries the **target triple, not the version** — the tag carries the
  version — so the download URL shape is stable across releases and a consumer bumps only
  the tag.
- The `.sha256` is `sha256sum` format (`<hash>  mint-x86_64-unknown-linux-gnu`), so
  `sha256sum -c` works directly against the downloaded file.
- Built with `--locked`, so the binary is reproducible from the tagged tree.
- The release job does **not** re-run fmt/clippy/test: a tag points at a commit that
  already passed `ci.yml` on its PR to `main`.

The shape is deliberately generic — `env.BIN` plus the build matrix are the only
repo-specific knobs — so the same workflow is intended to be reused for other repos' (e.g.
elide's) binaries.

## Tag conventions

- **Final release** — `vX.Y.Z`. Published as a normal release; GitHub badges the highest
  such tag "Latest".
- **Pre-release** — a semver tag with a hyphen (`vX.Y.Z-rc1`, `-alpha.2`, `-beta`). The
  workflow detects the hyphen (SemVer 2.0.0: everything after the first hyphen is the
  pre-release identifier) and publishes with `--prerelease`, so it is **never** badged
  "Latest". GitHub does not infer this from the tag name on its own — the workflow sets the
  flag.
- The trigger fires on the **tag, not a branch**. A release can be cut from any branch, as
  long as the tagged commit contains `release.yml` (GitHub runs the workflow as it exists
  in the tagged commit).

## Cutting a release

```sh
git tag -a v0.1.0 -m "mint v0.1.0"
git push origin v0.1.0
```

To dry-run the pipeline without publishing a "Latest" release, push a pre-release tag,
inspect the result, then delete it:

```sh
git tag -a v0.1.0-rc1 -m "RC" && git push origin v0.1.0-rc1
gh release view v0.1.0-rc1 --json isPrerelease,assets   # prerelease: true, two assets
gh release delete v0.1.0-rc1 --cleanup-tag --yes         # removes the release + remote tag
git tag -d v0.1.0-rc1
```

## Consuming the artifact in a deployment

1. **Download** the binary (and, for transit integrity, the `.sha256`) from the release
   URL for your pinned `<tag>`.
2. **Verify the checksum.** Two postures:
   - *Fetch-and-check* — download the `.sha256` and `sha256sum -c` it. Guards against
     transit corruption only.
   - *Pinned digest* (**recommended for deploys**) — store the expected SHA-256 in your
     deploy repo and check against it: `echo "<sha256>  <asset>" | sha256sum -c -`. The
     fetched `.sha256` lives in the same release as the binary, so an actor who can replace
     the binary can replace its checksum too; a digest pinned in your own repo can't be
     swapped that way. Each version bump then updates the tag *and* the digest together.
3. **Mind the glibc base** (above) — keep the runtime on a glibc distro ≥ the builder's.
4. **Render with the same binary if needed.** If the deployment renders role templates
   (`mint render` bakes `{{build.X}}` deployment constants), it already has the binary in
   hand — render before assembling the runtime image.

The v0.1.0 binary's sha256 is
`e54f14be734d10b30191cfc6f3eda73f22ee399d23a05005eea90df6433ee1ca`.

## Worked example: elide's Fly image

elide's `deploy/mint/` (in the elide repo — land the change there) builds the Fly image.
It currently compiles mint from source: rustup + `build-essential`, `git clone` at a pinned
commit SHA (`MINT_REF`), `cargo build --release` — minutes per `fly deploy`. Switching to
the artifact replaces that with a download + verify, keeping the `mint render` step.

**`deploy/mint/Dockerfile`** — rename the build arg `MINT_REF` (SHA) → `MINT_VERSION`
(tag), and replace the build stage's toolchain/clone/compile with a download. The build
stage still runs `mint render`, so it downloads the binary, renders, and the runtime stage
copies it across:

```dockerfile
ARG MINT_VERSION=v0.1.0

FROM ubuntu:24.04 AS build
ARG MINT_VERSION
# curl + CA certs only — no rust toolchain, git, or build-essential.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

ARG MINT_ASSET=mint-x86_64-unknown-linux-gnu
ARG MINT_BASE=https://github.com/soulware/mint/releases/download
# Pinned-digest verify (preferred). For the fetch-and-check form, curl the
# "${MINT_ASSET}.sha256" alongside and `sha256sum -c "${MINT_ASSET}.sha256"`.
ARG MINT_SHA256=e54f14be734d10b30191cfc6f3eda73f22ee399d23a05005eea90df6433ee1ca
RUN curl --proto '=https' --tlsv1.2 -fsSLO "${MINT_BASE}/${MINT_VERSION}/${MINT_ASSET}" \
 && echo "${MINT_SHA256}  ${MINT_ASSET}" | sha256sum -c - \
 && install -m 0755 "${MINT_ASSET}" /usr/local/bin/mint

ARG DATA_BUCKET=elide
COPY role-templates/ /role-templates/
RUN mint render --in-dir /role-templates --build "bucket=${DATA_BUCKET}" --out-dir /roles
```

In the runtime stage, the binary copy source moves from `/src/target/release/mint` to
`/usr/local/bin/mint`:

```dockerfile
COPY --from=build /usr/local/bin/mint /usr/local/bin/mint
```

Everything else in the runtime stage (`/roles` copy, `mint-fly.toml`, the `STORE_BUCKET`
sed, `MINT_CONFIG`, `EXPOSE`, `CMD`) is unchanged. Update the Dockerfile header comment too
— it currently claims "mint publishes no release artifact," which is no longer true.

**`deploy/mint/fly.toml.example`** — under `[build.args]`, replace `MINT_REF = "<sha>"`
with `MINT_VERSION = "v0.1.0"` (and `MINT_SHA256` if pinning the digest), and update the
surrounding comment.

**`deploy/mint/README.md`** — reword the prose that says the image "builds the stock `mint`
from the pinned `MINT_REF`" to "downloads and checksum-verifies the released `mint` binary
at `MINT_VERSION`"; change the build-args bullet `MINT_REF (lockstep mint commit)` →
`MINT_VERSION (released mint tag, e.g. v0.1.0)`. Keep the role-templates "lockstep with the
coordinator" framing — that's about the templates, independent of how the binary is
obtained.

**Out of scope.** The `attested-e2e` CI job uses the **`mint-e2e` harness binary**, built
from source with `--features e2e-harness`. That harness is *not* a published artifact (the
release ships only the `mint` bin), so leave that job building from source.

**Verify:**

```sh
cd deploy/mint
docker build --build-arg MINT_VERSION=v0.1.0 --build-arg DATA_BUCKET=<bucket> -t mint-elide:test .
docker run --rm mint-elide:test mint --help    # binary runs in the runtime image
docker run --rm mint-elide:test ls /app/roles  # rendered roles present
```

The build should drop from minutes to seconds (download + render only).
