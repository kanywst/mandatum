# Project infrastructure

Last updated: 2026-09-13.

[GOVERNANCE.md](../../GOVERNANCE.md) §5.4 says project infrastructure must not be owned by an individual or a company in a way that could be used as leverage, and that it transfers with the project on donation to a foundation. This is the list, with who holds each piece today.

It is not a comfortable list, and that is the point of writing it down. A neutrality claim nobody can check is a slogan.

## What exists

| Piece | Custodian today | On donation |
| --- | --- | --- |
| Source repository | `github.com/kanywst/mandatum`, a personal account | Transfers to the foundation's organization |
| Issue tracker, pull requests, discussions | Same repository | Transfers with it |
| CI/CD | GitHub Actions, defined in `.github/workflows/`, no self-hosted runners | Transfers with the repository |
| Release signing | Sigstore keyless. No key is held by anyone | Nothing to transfer; see below |
| Release artifacts | GitHub Releases on the same repository | Transfers with it |
| Go module path | `github.com/kanywst/mandatum` | Changes on transfer, which is a breaking change for importers; see [VERSIONING.md](../../VERSIONING.md) |
| Domain name | None | — |
| Website | None | — |
| Container images | None published | — |
| Social and communication accounts | None | — |

## Signing holds no key

Releases are signed with cosign in keyless mode: the workflow exchanges a GitHub OIDC token for a short-lived Sigstore certificate, signs, and the certificate expires. There is no private key in a secret, on a maintainer's laptop, or anywhere else.

That is worth stating in a document about custody, because a signing key is the one piece of infrastructure whose transfer is genuinely hard. Here there is nothing to hand over: an adopter verifies against the workflow identity, and that identity moves when the repository does. The verification command in [supply-chain.md](../security/supply-chain.md) pins that identity, so it has to be updated on transfer — which is the intended behaviour rather than an oversight. A release signed by the old location should stop verifying under the new one.

## Secrets

One repository secret, `CLAUDE_CODE_OAUTH_TOKEN`, used by the review workflow. It is a convenience and nothing depends on it: the workflow fails loudly without it, and no release, test, or publication path touches it.

## The honest part

Everything above sits under one personal GitHub account. One person can push to the default branch, cut a release, and change these workflows.

Branch protection requires 19 status checks and refuses force pushes, but `enforce_admins` is off, because a single maintainer who locks themselves out has no second maintainer to let them back in. That trade is deliberate and it is a real gap, not a mitigated one.

This is the same fact [GOVERNANCE.md](../../GOVERNANCE.md) §5.3 and [supply-chain.md](../security/supply-chain.md) record from their own angles, and the reason maintainers from a second organization is a release-blocking gate for v1.0 in [ROADMAP.md](../../ROADMAP.md) rather than an aspiration.
