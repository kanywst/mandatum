# Contributing to Mandatum

Thanks for considering a contribution. This document covers what the project needs, how to get a change merged, and the standards a change is held to.

Project roles and how decisions get made are in [GOVERNANCE.md](GOVERNANCE.md). Security reports go through [SECURITY.md](SECURITY.md), not the issue tracker.

## What the project most needs right now

Mandatum is early. The most valuable contributions today are not code:

- **Review the specification.** [`docs/spec/delegation-assertion.md`](docs/spec/delegation-assertion.md) has an open-questions section. Disagreement with the design, especially from people who have operated agent systems in production, is more useful at this stage than an implementation of the current design.
- **Tell us it already exists.** If another project already solves rooted delegation, sequence-level constraints, and AuthZEN binding, that is worth knowing before more is built. Open an issue; see `docs/alternatives.md`.
- **Bring a real scenario.** A concrete description of an agent deployment and what you could not express with existing tooling.

## Before you start

For anything larger than a typo, open an issue first and get agreement on the approach. This is to avoid the situation where someone spends a weekend on a change the project cannot take. Small, obvious fixes can go straight to a pull request.

Issues labelled `good first issue` are scoped so that they can be completed without deep context, and each states what "done" looks like.

## Development

Requirements: Go 1.24 or newer (the `go` directive in `go.mod` is the minimum, and `VERSIONING.md` says so), `make`, and three things `make verify` will not run without: `golangci-lint`, `go-licenses`, and Node for `npx markdownlint-cli2`. The first two exit 127 rather than skipping, because a lint step that quietly does nothing is worse than one that fails.

```bash
make build     # compile
make test      # unit tests with race detector
make lint      # golangci-lint
make fuzz      # short fuzzing pass over the verifier
make verify    # the subset of CI you can usefully run locally
```

Run `make verify` before opening a pull request. It is a subset, not the merge gate: it covers the checks that fail most often and run fastest locally. CI additionally runs, on every pull request, all of

- the coverage floor, the race detector on macOS and Windows and against `oldstable`, and `go mod tidy` leaving the tree clean;
- `make fuzz` — which `verify` deliberately leaves out because it is slow, so run it yourself when touching parsing or verification;
- `govulncheck`, CodeQL, `actionlint`, `zizmor`, `shellcheck`, `codespell`, and two link checkers;
- a sign-off on every commit (`git commit -s`), the unmodified `LICENSE`, and dependency review.

A green `make verify` means the fast checks pass, not that the merge will be green.

## Standards for a change

- **Tests.** New behaviour needs tests. A bug fix needs a test that fails before the fix. Verification logic needs both positive and negative cases, because a verifier that accepts everything passes every positive test.
- **Specification first.** A change to the wire format, to verification, or to attenuation must update `docs/spec/` in the same pull request. The specification is normative; the code follows it.
- **No document that does not exist.** A sentence claiming something is recorded in another file must be about a file that exists, or that file must be listed as Planned in [docs/README.md](docs/README.md). CI checks it, because whoever writes such a sentence intends to write the file and is therefore the last to notice it is missing. It has happened three times here.

  A link is held to the stricter standard: it must resolve, even to a document declared Planned. A reader who clicks it gets a dead end whatever the table says, so an unwritten document may be mentioned in prose and not linked.
- **No silent fail-open.** Any code path that cannot complete a check must deny. A pull request that introduces a path where a failure results in allowing an action will not be merged, regardless of how unlikely the failure is.
- **Dependencies.** Adding a dependency requires justification in the pull request. Its license must be on the CNCF allowlist, including transitively; CI enforces this. Prefer the standard library.
- **Commits.** Conventional-commits style (`feat(verify): ...`, `fix: ...`, `docs: ...`). One logical change per commit; do not mix refactoring with behaviour changes.

## Pull requests

1. Fork and create a branch.
2. Make the change, with tests and specification updates.
3. Run `make verify`.
4. Open the pull request. Describe what problem it solves and how you know it works. Link the issue.
5. Address review. Push additional commits rather than force-pushing during review, so reviewers can see what changed.

Every pull request needs approval from an Approver for the areas it touches, and changes to the verifier, the wire format, or cryptographic handling need approval from a Maintainer.

That rule has nobody to apply it yet. There are no Approvers, there is one Maintainer, and `main`'s branch protection requires status checks but not a review — so every pull request merged so far was merged by its own author. The rule is written down because it is what the project intends to run under, not because it is running. Until a second Maintainer exists, an outside contributor's pull request is reviewed by the Maintainer and the Maintainer's own is reviewed by CI and whoever comments, which is a real weakness and is listed as one in `docs/security/supply-chain.md`.

## Language

English is the project's working language and the normative one. Issues and pull request descriptions may be written in any language you are comfortable with — someone will translate. Commit messages, code comments, and changes under `docs/spec/` must be in English, because the specification needs exactly one authoritative version.

Translations are welcome and are governed by [docs/i18n.md](docs/i18n.md). Where a translation disagrees with the English text, the English text is correct; for a security specification that is a safety property, not a preference.

## Sign-off

All commits must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "fix(verify): reject chains with a rewritten root"
```

This adds a `Signed-off-by` line and certifies you have the right to submit the work under the project's license. CI checks for it.

## License

Contributions are licensed under Apache License 2.0, the same as the project. See [LICENSE](LICENSE).
