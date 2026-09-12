# Changelog

Notable changes to Mandatum. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](VERSIONING.md).

Each release also records which Delegation Assertion format versions (`mdt.v`) it accepts and issues, because verifiers and issuers are upgraded separately.

## [Unreleased]

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

[Unreleased]: https://github.com/kanywst/mandatum/commits/main
