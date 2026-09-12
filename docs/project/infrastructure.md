# Project infrastructure

Last updated: 2026-09-13.

[GOVERNANCE.md](../../GOVERNANCE.md) §5.4 says project infrastructure must not be owned by an individual or a company in a way that could be used as leverage, and that it transfers with the project on donation to a foundation.

This document answers one question that is not answered anywhere else: **for each piece, who holds it, and what happens to it on transfer.** It deliberately does not restate what other files already say. Where a fact lives somewhere authoritative, this points there instead of copying it, because a copied fact is a fact that goes stale silently.

## Custody and transfer

| Piece | Held by | On donation |
| --- | --- | --- |
| Source repository, issues, pull requests, discussions | The account named in `security-insights.yml` under `project-url` | Transfers to the foundation's organization |
| CI/CD | GitHub Actions, defined in `.github/workflows/`; no self-hosted runners | Transfers with the repository |
| Release signing | Nobody. See below | Nothing to transfer |
| Transparency log entries | Nobody. Sigstore's public log, append-only, not the project's to hold or withdraw | Nothing to transfer; the entries stay valid and keep naming the old workflow identity |
| Release artifacts | GitHub Releases on the same repository | Transfers with it |
| Go module path | The repository path | Changes on transfer, which breaks importers. See [VERSIONING.md](../../VERSIONING.md) |
| Domain name, website, container registries, social accounts | None exist | Nothing to transfer |
| Repository secrets | The repository. What they are and whether anything depends on them is below | Transfer with it, or are re-created |

## Signing holds no key

Releases are signed keyless: the workflow exchanges a GitHub OIDC token for a short-lived Sigstore certificate. The mechanism and the verification command are in [supply-chain.md](../security/supply-chain.md); what matters here is the custody consequence.

A signing key is normally the hardest piece to hand over. There is nothing to hand over. An adopter verifies against the workflow identity, and that identity moves when the repository does — so the verification command has to be updated on transfer, and releases signed at the old location stop verifying under the new one. That is intended. A signature that survived a change of custodian would be worth less, not more.

Transparency log entries are the same shape of answer from the other direction: they are public, append-only, and not the project's property. Nobody can withdraw them, including whoever holds the repository.

## Secrets

CI does not require any secret to build, test, sign or release. The only one configured is for the review workflow, which fails loudly when it is absent rather than passing quietly.

Rather than enumerate secrets here, where the list would go stale the first time one is added: the authoritative list is the repository's own settings, and what CI actually consumes is greppable as `secrets.` in `.github/workflows/`. A secret that no workflow references is a finding in itself.

## The honest part

Everything above sits under one personal account. One person can push to the default branch, cut a release, and change these workflows. [GOVERNANCE.md](../../GOVERNANCE.md) §5.3 and [supply-chain.md](../security/supply-chain.md) record the same fact for their own purposes; this document does not restate the consequences they already draw.

The custody-specific consequence is the one worth adding: **there is no second party to transfer to today.** Donation is not blocked by anything technical here — no key, no domain, no vendor account — but it is not a handover between organizations either, because there is only one. That is why maintainers from a second organization is a release-blocking gate for v1.0 in [ROADMAP.md](../../ROADMAP.md) rather than an aspiration.

Branch protection is on, requires the CI checks to pass, and refuses force pushes and deletions. `enforce_admins` is off, because a lone maintainer who locks themselves out has no second maintainer to let them back in. The exact settings live in the repository, not in this file, so that this file cannot disagree with them.
