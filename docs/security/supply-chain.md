# Supply chain

What this project does to make its own artifacts verifiable, and how to check that it did it. Referenced from [SECURITY.md](../../SECURITY.md).

## Dependencies

The verification core depends only on the Go standard library. That is a deliberate constraint, not a coincidence of being early: the code that decides whether a chain grants authority should be reviewable without also reviewing someone else's parser.

Adding a dependency requires justification in the pull request. Its license must be on the CNCF allowlist, transitively, which CI enforces on every pull request and again weekly — upstream projects relicense without anything changing on this side.

Signature verification and revocation lookup are interfaces precisely so that a JOSE implementation, which is a real dependency with real surface area, sits outside the part that must be audited most closely.

## What every release carries

| Artifact | Purpose |
| --- | --- |
| `mandatum-vX.Y.Z.tar.gz` | Source archive built from the signed tag. |
| `mandatum-sbom.spdx.json` | SPDX SBOM. |
| `checksums.txt` | SHA-256 of every artifact. |
| `checksums.txt.sig`, `checksums.txt.pem` | Cosign keyless signature and certificate. |
| Build provenance attestation | Attests which workflow, at which commit, produced the archive. |

Only the checksum file is signed. It transitively covers every artifact, and leaves one signature to verify rather than one per file.

## Verifying a release

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
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
| Build, unit tests with the race detector | every push and pull request |
| `golangci-lint` | every push and pull request |
| Fuzzing of parsing and chain verification | every pull request, and before release |
| CNCF dependency license allowlist | every push and pull request, plus weekly |
| `govulncheck` | every push and pull request, plus weekly |
| CodeQL, `security-extended` | every push and pull request |
| OpenSSF Scorecard | default branch |
| Developer Certificate of Origin sign-off | every pull request |
| Changelog entry exists for the tag | before publishing a release |
| `LICENSE` is the unmodified Apache-2.0 text | every push and pull request |

The release workflow re-runs the build, the tests and the license check on the tag rather than trusting the pull request that produced it, because the thing being published is the tag.

## Known gaps

Stated because a supply-chain document that lists only strengths is marketing.

- **No third-party security review.** One is a required gate for v1.0. Until then the verifier is unreviewed by anyone outside the project.
- **Single maintainer.** One person can currently push to the default branch and cut a release. This is the strongest argument against depending on Mandatum today, and it is why maintainers from a second organization is a v1.0 gate rather than an aspiration.
- **No reproducible builds.** The source archive is deterministic because it is `git archive`, but there are no compiled artifacts yet, so the harder question has not been answered.
- **`@latest` tooling.** `go-licenses` and `govulncheck` are installed at `@latest` in CI. That keeps vulnerability data current but means the toolchain is not pinned. Pinning is tracked for v0.2, along with whether pinning a vulnerability scanner is actually desirable.
