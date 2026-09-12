# Changelog

Notable changes to Mandatum. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](VERSIONING.md).

Each release also records which Delegation Assertion format versions (`mdt.v`) it accepts and issues, because verifiers and issuers are upgraded separately.

## [Unreleased]

Wire format: accepts `mdt.v` 1, issues `mdt.v` 1.

### Added

- Delegation Assertion format specification, covering the wire format, the six attenuation rules, verification rules V1 through V9, the AuthZEN binding, sequence evaluation, and a threat model.
- `pkg/mda`: the assertion types and structural validation.
- `pkg/verify`: chain verification implementing V1 through V9, with denials that name the specification rule that produced them.
- Alternatives analysis covering fourteen adjacent projects and standards.
- Governance with an organizational voting cap, applied from the start rather than at Graduation.
- CI enforcing the CNCF dependency license allowlist, re-checked weekly.
- Continuous fuzzing of assertion parsing and chain verification.

### Known limitations

- No JOSE binding yet: `SignatureVerifier` is an interface with no production implementation in-tree, so nothing here verifies a real signature.
- Sequence constraints are represented and attenuated but not yet evaluated; there is no sequence store.
- No audit log.
- Rule V7 is not reachable through the public API. V5 and the structural `max_depth` invariant reject anything that would violate it first. It is retained as defence in depth and tested directly.

[Unreleased]: https://github.com/kanywst/mandatum/commits/main
