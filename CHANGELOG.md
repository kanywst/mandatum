# Changelog

Notable changes to Mandatum. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](VERSIONING.md).

Each release also records which Delegation Assertion format versions (`mdt.v`) it accepts and issues, because verifiers and issuers are upgraded separately.

## [Unreleased]

### Added

- `pkg/authzen`: an OpenID AuthZEN Authorization API 1.0 client and the mapping from a verified chain onto an Access Evaluation request, following the COAZ-MCP default mapping for `tools/call`. PDP metadata discovery included, with the mix-up check the PDP identifier exists for.
- `verify.Result.Actors`: the principals a chain's authority passed through, from the sponsor's grantee to the acting agent.

### Changed

- The specification's AuthZEN example now matches the COAZ-MCP binding: the human sponsor is `subject`, the acting agent is `context.agent`, and the rest of the chain sits under a vendor-prefixed context key because the binding leaves upstream actors undefined rather than forbidding them. The previous example invented `subject.type: "agent"` and `resource.type: "mcp_tool"`, which is exactly the parallel mapping the non-goals say not to define.
- The Japanese specification and README caught up with changes made to the English originals after they were translated. The drift check only runs on pull requests, and those changes went straight to `main`.

## [0.1.0-rc.2] - 2026-09-12

A pre-release, on the same terms as rc.1: no compatibility promise, not supported.

Wire format: accepts `mdt.v` 1, issues `mdt.v` 1. Unchanged from rc.1 — this release exists only to fix the signing step, which is why rc.1 never published.

### Fixed

- The release workflow signed nothing. cosign v3 deprecated `--output-signature` and `--output-certificate` and ignores them when writing the new bundle format, so the step failed outright rather than quietly producing an unsigned release — but only because it also errored on the empty `--bundle` path. Releases now write a Sigstore bundle, and the verification instructions match.

## [0.1.0-rc.1] - 2026-09-12

A pre-release. Per [VERSIONING.md](VERSIONING.md) it carries no compatibility promise and is not supported.

It exists to exercise the release path — signing, SBOM, provenance, the changelog gate — before a release where getting that wrong would matter. It is not v0.1.0: that version's gates in [ROADMAP.md](ROADMAP.md) require fuzzing to run clean for 24 hours, and the nightly campaign has not done that yet. Gates are commitments, so the version number waits for them.

Wire format: accepts `mdt.v` 1, issues `mdt.v` 1.

### Added

- Delegation Assertion format specification, covering the wire format, the six attenuation rules, verification rules V1 through V9, the AuthZEN binding, sequence evaluation, and a threat model.
- `pkg/mda`: the assertion types and structural validation.
- `pkg/verify`: chain verification implementing V1 through V9, with denials that name the specification rule that produced them.
- `pkg/jose`: a deliberately narrow JWS implementation supporting only EdDSA over Ed25519 and the `mdt+jwt` media type, so algorithm confusion has no code path to reach.
- `pkg/issue`: building and signing chains, applying the same attenuation rules the verifier applies so an over-broad delegation fails at the desk of whoever wrote it.
- Digest encoding fixed as unpadded base64url, with test vectors published in the specification and pinned by tests so the two cannot drift.
- Threat model, supply-chain documentation, and Japanese translations of the README and the specification.
- Alternatives analysis covering fourteen adjacent projects and standards.
- Governance with an organizational voting cap, applied from the start rather than at Graduation.
- CI enforcing the CNCF dependency license allowlist, re-checked weekly.
- Continuous fuzzing of assertion parsing and chain verification.

### Fixed

- `issue.Delegate` accepted a child claiming capabilities its parent never held, and a child that raised its own sequence budget, despite the package documenting that it checked both. Found by the documentation example. The rules now have one implementation, `verify.Attenuates`, called by the issuer and the verifier.
- `max_depth` had two incompatible readings: an absolute chain bound and a per-link budget. Combined with the per-hop decrease, the pair silently halved the usable delegation depth. It is now unambiguously "further delegations permitted below this assertion", and specification section 5.3 explains why it is not tied to `depth`.

### Known limitations

- Sequence constraints are represented, attenuated and carried through verification, but not yet evaluated; there is no sequence store. Do not rely on `mdt.seq` for enforcement.
- No audit log.
- Rule V7 is not reachable through the public API. V5 and the structural `max_depth` invariant reject anything that would violate it first. It is retained as defence in depth and tested directly.

[Unreleased]: https://github.com/kanywst/mandatum/compare/v0.1.0-rc.2...HEAD
[0.1.0-rc.2]: https://github.com/kanywst/mandatum/releases/tag/v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/kanywst/mandatum/releases/tag/v0.1.0-rc.1
