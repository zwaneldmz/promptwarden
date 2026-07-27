# Releasing Wardkeep

**Note:** `.github/workflows/release.yml` has never been exercised by an actual tag push — GitHub
Actions cannot run in the environment that authored it. Every step was validated the ways it could
be: syntax-checked, and the packaging/checksum/verification logic was run for real locally against
this repo's actual build output (see the PR that introduced this file for the exact commands and
output). The cosign signing, the build-provenance attestation, and the `gh release create` call
itself are unverified until the first real tag push runs them end to end. Treat the first release
as the actual test of this pipeline, and skim the workflow file before trusting it blindly.

This is the human procedure: what to bump, how to tag, what the workflow then does automatically,
and — the part that matters most for a security tool — the exact commands a **user** runs to
verify a downloaded release before installing it.

## Version bump locations

Three files carry a version number. The release workflow refuses to tag a release unless the tag
and both of the first two agree — bump both before tagging:

| File | Field | Notes |
|---|---|---|
| `apps/extension/manifest.json` | `"version"` | What Chrome/Edge shows for the installed extension. Must match the tag. |
| `apps/cli/package.json` | `"version"` | What `npm view`/`npm install` and the packed tarball's filename show. Must match the tag. |
| `package.json` (repo root) | `"version"` | The private monorepo root's own version. Not read by the release workflow and not required to match — bump it too, by convention, so it doesn't silently drift, but a mismatch here won't block a release. |

There is no automated version-bump script yet. Edit both required files by hand, commit, then tag
(below). If you forget one, the release workflow's first job step fails fast with the exact
mismatch, before anything is built, signed, or published — see "Resolve and validate release
version" in `release.yml`.

## Tagging convention

Tags are `vMAJOR.MINOR.PATCH` — plain semver with a `v` prefix, nothing else. The workflow's
version-resolution step rejects any tag that doesn't match `^v[0-9]+\.[0-9]+\.[0-9]+$` (no
pre-release/build suffixes yet; if you need `v0.2.0-rc1`-style tags later, that regex and the
docs below both need updating together).

```bash
git checkout main
git pull

# Bump apps/extension/manifest.json and apps/cli/package.json to 0.2.0, commit that.
git add apps/extension/manifest.json apps/cli/package.json
git commit -s -m "Bump version to 0.2.0"
git push origin main

git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

Pushing the tag is what triggers `release.yml` — there is no separate "click to release" step.
An annotated tag (`-a`, with a message) is used above so the tag itself carries who cut it and
why; a lightweight tag also triggers the workflow if that's what you push, but won't have that.

## What the release workflow does

On a `v*` tag push (or a manual `workflow_dispatch` re-run against an existing tag — see
"Recovering from a failed or partial release" below), `.github/workflows/release.yml`:

1. **Checks out the tagged commit** and validates the tag against `apps/extension/manifest.json`
   and `apps/cli/package.json` as described above.
2. **Runs the same gates `ci.yml` runs** — typecheck, the full test suite (including the <10ms
   inline-path bench gate), the extension build, the CLI build, the no-egress gate, and the
   fixture-hygiene gate. A release cannot ship something CI would have rejected; if any of these
   fail, nothing is packaged, signed, or published.
3. **Packages the extension** as a zip containing only what the extension needs to run —
   `manifest.json`, the two built bundles (`background.js`, `content.bundle.js`), `popup.html`,
   `popup.js`, `managed_schema.json`, and `icons/` — never `src/`, `tsconfig.json`, or
   `node_modules`. Named `wardkeep-extension-vX.Y.Z.zip`.
4. **Packs the CLI** with a plain `npm pack` inside `apps/cli` (its `package.json` already scopes
   `"files"` to `dist/` only). Named `wardkeep-X.Y.Z.tgz`.
5. **Writes `SHA256SUMS`** — the SHA-256 of both artifacts above, one line each, in the standard
   `sha256sum`/`shasum -c`-compatible format.
6. **Signs `SHA256SUMS` with cosign, keylessly** — no private key is generated, stored, or
   rotated by anyone. Cosign exchanges the job's GitHub Actions OIDC token for a short-lived
   Sigstore Fulcio certificate identifying this exact repo, workflow file, and tag, signs with an
   ephemeral keypair thrown away immediately after, and publishes the signing event to the public
   Rekor transparency log. Output: `SHA256SUMS.sig` (the signature) and `SHA256SUMS.pem` (the
   short-lived certificate — needed at verification time, see below).
7. **Attests build provenance** via `actions/attest-build-provenance`, covering both artifacts
   listed in `SHA256SUMS` in one call. This is a second, independent, GitHub-native trail (backed
   by the same Sigstore infrastructure) recording that these exact bytes came from this exact
   workflow run, on this exact commit, and were not hand-assembled or uploaded from someone's
   laptop.
8. **Publishes the GitHub release** for the tag, with all five files attached: both artifacts,
   `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.pem`.

The job's permissions are `contents: write` (create the release, upload assets), `id-token: write`
(the OIDC token cosign and attest-build-provenance need), and `attestations: write` (publish the
provenance attestation) — nothing else. No `packages:`, `issues:`, or `pull-requests:` access.

## Verifying a release (for users)

Do this before installing either artifact — that's the entire point of signing them. You need
`cosign` installed locally (see [Sigstore's install docs](https://docs.sigstore.dev/cosign/system_config/installation/)) and, for the provenance check, the `gh` CLI.

### 1. Check the checksums

Download `SHA256SUMS` alongside whichever artifact(s) you downloaded, then, from the directory
holding both:

```bash
sha256sum -c SHA256SUMS     # Linux
# or
shasum -a 256 -c SHA256SUMS # macOS
```

This only tells you the files weren't corrupted or truncated in transit — it says nothing about
who produced them. That's what the signature is for.

### 2. Verify the cosign signature over SHA256SUMS

Download `SHA256SUMS.sig` and `SHA256SUMS.pem` too, then:

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/zwaneldmz/wardkeep/.github/workflows/release.yml@refs/tags/v0.2.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  SHA256SUMS
```

Replace `v0.2.0` with the actual tag of the release you downloaded — `--certificate-identity` has
to match exactly, because that's the whole point: it's asserting "this was signed by a run of
*this specific workflow file*, triggered by *this specific tag*," not just "signed by cosign, by
someone." A successful verification prints `Verified OK`.

If you'd rather verify against *any* release this pipeline has produced without editing the tag
by hand each time, use a regexp instead:

```bash
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/zwaneldmz/wardkeep/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  SHA256SUMS
```

A `SHA256SUMS` that verifies covers both artifacts transitively — you already confirmed their
hashes match `SHA256SUMS` in step 1.

### 3. (Optional, stronger) Verify the build provenance attestation

This checks the second, independent trail — that GitHub itself attests these bytes came from a
specific workflow run on a specific commit, not just that *some* Sigstore-issued certificate
signed them:

```bash
gh attestation verify wardkeep-extension-v0.2.0.zip -R zwaneldmz/wardkeep
gh attestation verify wardkeep-0.2.0.tgz -R zwaneldmz/wardkeep
```

Requires a `gh` CLI recent enough to have the `attestation` subcommand.

## Chrome Web Store re-signing — a verified zip is not the same artifact the store ships

**`wardkeep-extension-vX.Y.Z.zip`, even fully verified by every step above, is not what a user
installs from the Chrome Web Store or Edge Add-ons, and never will be, by construction.** The zip
this workflow produces is *packing input* — the exact runtime files, unsigned, meant for
self-hosted CRX packing (`docs/DEPLOY_SELF_HOSTED_CRX.md`) or for a security-conscious user who
wants to inspect exactly what they're about to load via `chrome://extensions` → Developer mode →
"Load unpacked."

The moment that same source is uploaded to the Chrome Web Store or Edge Add-ons, the store
**re-signs it with a key you never see**, and the resulting extension ID is derived from that
store key's public half — not from anything in this zip, not from anything cosign signed. That
means:

- The self-hosted zip's extension ID, the Chrome Web Store build's extension ID, and the Edge
  Add-ons build's extension ID are **three different IDs** for the same source code (see
  `docs/DEPLOY_SELF_HOSTED_CRX.md`'s warning section for the operational consequences of that —
  managed policy is keyed per-ID, so it matters which one a fleet is actually running).
- Verifying this zip's signature tells you the *source Wardkeep published* is authentic. It
  tells you nothing about the bytes the Chrome Web Store actually served to a given user on a
  given day — that step is entirely Google's/Microsoft's trust chain, not this project's. If you
  need cryptographic assurance over what a fleet is actually running, deploy the self-hosted CRX
  from a verified build, not the store listing.
- There is currently no store listing for either browser (see the placeholder extension IDs in
  `docs/DEPLOY_GOOGLE_ADMIN.md`, `docs/DEPLOY_INTUNE.md`, `docs/DEPLOY_GPO.md`) — until one ships,
  this distinction is forward-looking, but it will be true the day a store listing exists, so it's
  documented now rather than discovered later.

## Known gaps — what "signed and verified" does not yet cover

Stated plainly, in the same spirit as this project's other honest-caveat headers:

- **Build reproducibility is partial.** The zip's own bytes are deterministic across independent
  builds of the same source — verified locally by staging and zipping the same input twice with
  fixed per-file timestamps and a sorted file list, producing byte-identical archives — but that
  was only verified with macOS's Info-ZIP `zip`, not independently confirmed against the
  `ubuntu-latest` runner's `zip` build. More importantly, the *inputs* to that zip aren't yet
  pinned: `package.json`'s devDependencies (`esbuild`, `typescript`, `@types/chrome`) are floating
  ranges, not exact versions (`docs/ROADMAP.md` item 21), so two CI runs on different days could
  legitimately produce different bundle bytes from identical source even though each run's own
  gates all pass. Signing proves "this is what *this run* of *this workflow* produced," not "this
  is the unique possible output of this source" — pinning the devDependency versions (a separate,
  not-yet-done change to `package.json`) is what closes that gap.
- **The no-egress and fixture-hygiene gate steps in `release.yml` are a manually maintained copy
  of `ci.yml`'s steps of the same name**, not a shared reusable workflow — the two files have
  different owners in this project's current change history, so extracting a
  `workflow_call`-based shared gate step was left as a follow-up rather than done as a drive-by
  change to `ci.yml`. If you change one, change the other, or the two will silently drift and this
  document's claim ("a release cannot ship what CI would reject") stops being true.
- **This workflow has not yet published a real release** (see the note at the top of this
  document). The packaging and checksum logic was verified locally; the signing, attestation, and
  `gh release create` steps have not been exercised against real GitHub Actions OIDC.
- **VS Code companion extension (`apps/vscode`) is not part of this pipeline.** It has no build
  script wired into the root `typecheck`/`test`/`build:*` commands yet, so there's nothing for
  this workflow to build, checksum, or sign for it today.

## Recovering from a failed or partial release

If a run fails **before** "Create GitHub release" (typecheck, tests, a gate, packaging, or
signing failed): nothing was published. Fix the problem, and either push a new commit and re-tag
(delete the bad tag first — `git tag -d vX.Y.Z && git push --delete origin vX.Y.Z` — then redo the
version bump/tag steps above), or re-run via `workflow_dispatch` with `ref: vX.Y.Z` if the tagged
commit itself didn't need to change.

If a run fails **during** "Create GitHub release" (e.g. the release object was created but an
asset upload was interrupted): check what actually landed —

```bash
gh release view vX.Y.Z -R zwaneldmz/wardkeep
```

Upload whatever's missing by hand (`gh release upload vX.Y.Z <file> -R zwaneldmz/wardkeep`),
or delete the release object without deleting the tag and re-run —

```bash
gh release delete vX.Y.Z -R zwaneldmz/wardkeep --cleanup-tag=false
```

— then trigger `workflow_dispatch` with `ref: vX.Y.Z`.
