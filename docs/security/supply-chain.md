# Supply chain

What this project does to make its own artifacts verifiable, and how to check that it did it. Referenced from [SECURITY.md](../../SECURITY.md).

## Dependencies

The verification core depends only on the Go standard library. That is a deliberate constraint, not a coincidence of being early: the code that decides whether a chain grants authority should be reviewable without also reviewing someone else's parser.

Adding a dependency requires justification in the pull request. Its license must be on the CNCF allowlist, transitively, which CI enforces on every pull request and again weekly — upstream projects relicense without anything changing on this side.

Signature verification and revocation lookup are interfaces precisely so that a JOSE implementation, which is a real dependency with real surface area, sits outside the part that must be audited most closely.

## What every release carries

| Artifact | Purpose |
| --- | --- |
| `mandatum-vX.Y.Z.tar.gz` | Source archive built from the tag, with `git archive`. The tag is annotated and **not** signed; see Known gaps. |
| `mandatum-sbom.spdx.json` | SPDX SBOM. |
| `checksums.txt` | SHA-256 of every artifact. |
| `checksums.txt.bundle` | Cosign keyless signature and certificate, as a Sigstore bundle. |
| Build provenance attestation | Attests which workflow, at which commit, produced the archive. |

Only the checksum file is signed. It transitively covers every artifact, and leaves one signature to verify rather than one per file.

## Verifying a release

```bash
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp 'https://github.com/kanywst/mandatum/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum -c checksums.txt

gh attestation verify mandatum-vX.Y.Z.tar.gz --repo kanywst/mandatum
```

The identity regexp matters. Verifying only that *something* signed the file proves nothing: anyone can obtain a Sigstore certificate. The check that carries weight is that the signer was this repository's release workflow.

## What CI enforces

| Check | When |
| --- | --- |
| Build, unit tests with the race detector | every pull request, and every push to `main` |
| `golangci-lint` | every pull request, and every push to `main` |
| Fuzzing of parsing and chain verification, 60s a target | every pull request, and on the tag before a release is published |
| Extended fuzzing campaign over every target, crashers retained | nightly |
| CNCF dependency license allowlist | every pull request, every push to `main`, and weekly |
| `govulncheck` | every pull request, every push to `main`, and weekly |
| CodeQL, `security-extended` | every pull request, every push to `main`, and weekly |
| OpenSSF Scorecard | default branch |
| Developer Certificate of Origin sign-off | every pull request except Dependabot's, which cannot sign off |
| The release notes build from the tag's changelog entry | before publishing a release, and again to write them |
| `LICENSE` is the unmodified Apache-2.0 text | every pull request, every push to `main`, and weekly |

The release workflow re-runs the build, the tests, a short fuzzing pass and the license check on the tag rather than trusting the pull request that produced it, because the thing being published is the tag.

Nothing here is a merge gate on its own. `main` is protected and the checks are required, but a repository administrator can override that, and this project currently has one.

## Known gaps

Stated because a supply-chain document that lists only strengths is marketing.

- **Tags are not signed.** Releases are cut from an annotated tag, and `git tag -v` on it reports no signature. The artifacts are signed — cosign keyless, with the bundle published alongside the checksums — so what a consumer verifies is the artifact and its provenance, not the tag it was built from. Anyone who can push a tag can therefore start a release. Signing tags, and having the release workflow refuse an unsigned one, is tracked for v0.2.
- **No third-party security review.** One is a required gate for v1.0. Until then the verifier is unreviewed by anyone outside the project.
- **Single maintainer.** One person can currently push to the default branch and cut a release. This is the strongest argument against depending on Mandatum today, and it is why maintainers from a second organization is a v1.0 gate rather than an aspiration.
- **No reproducible builds.** The source archive is deterministic because it is `git archive`, but there are no compiled artifacts yet, so the harder question has not been answered.
- **`@latest` tooling.** Every GitHub Action is pinned to a commit SHA with the version in a trailing comment, and Dependabot updates the pins. Two things are still installed at `@latest` in CI: `go-licenses` and `govulncheck`. For a vulnerability scanner that is arguably correct — a pinned scanner stops learning about new vulnerabilities — but it is an unpinned input to the build and is recorded here as one. Resolving it is tracked for v0.2.
