# Changelog

Notable changes to Mandatum. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](VERSIONING.md).

Each release also records which Delegation Assertion format versions (`mdt.v`) it accepts and issues, because verifiers and issuers are upgraded separately.

## [Unreleased]

### Added

- `jose.JWKS`: key resolution by fetching an issuer's published document, which is what §7 rule V3 has always described and no code did. It reads a plain JWKS or a SPIFFE trust domain bundle, accepts only Ed25519 keys published for verification, caches with a TTL, refetches once when an assertion carries an unseen `kid` so a rotation is picked up before the TTL expires, and rate-limits that refetch so a forged `kid` cannot turn one request into one fetch. A document that sits below the highest `spiffe_sequence` seen for that issuer is refused, since an older bundle can carry a key that has since been retired - including a document that declares no sequence at all, because absent reads as below everything and stripping the member would otherwise reset the ratchet. Fetches for one issuer are serialized, so a burst of assertions naming an unseen key costs one request rather than one each. Which document belongs to which issuer is configuration; it is never read from the assertion and never found by dereferencing the issuer identifier. `jose.KeyRing` is unchanged and remains right for a deployment that pins keys by hand.
- `pkg/revoke`: the compact revocation set of §7.1, so a PEP evaluates V8 locally instead of calling a service on the path of every authorized action. A Bloom filter has no false negatives, so the identifier that is not revoked — every call in a healthy system — is answered from memory with no lookup at all. A filter hit is resolved against an exact lookup where one is configured, and denies where one is not, which is what the specification says. A set older than the deployment's maximum age is an error rather than an empty set, and a set whose sequence has gone backwards is refused.
- §7.1 now specifies the set's encoding and bit derivation normatively. It described a mechanism in the present tense for weeks without saying how to build one, and two implementations that index bits differently produce sets neither can read — a failure whose shape is that one of them stops honouring revocations rather than that it errors.
- `verify.Result.Permits`: the check that bounds what a policy decision can mean. The specification said a compromised PDP could deny but never widen, "enforced by ordering"; nothing compared a request against the chain's capability set, and `Result.Capabilities` was read by no code outside tests. A PEP following the documented flow would have performed a tool call no sponsor granted, if a PDP said yes. The bound is still not automatic - it holds where the enforcement point makes this call - and §8, §11 and the threat model now say so instead of implying the format provides it.
- `pkg/sequence`: evaluation of `mdt.seq` against a chain's action history, keyed on the chain root so a constraint survives sub-delegation and cannot be reset by spawning another agent. Invocation budgets and forbid-after constraints are enforced; the store is in-process only, which is stated in the README's status block and is a v0.2 item.
- `pkg/authzen`: an OpenID AuthZEN Authorization API 1.0 client and the mapping from a verified chain onto an Access Evaluation request, following the COAZ-MCP default mapping for `tools/call`. PDP metadata discovery included, with the mix-up check the PDP identifier exists for.
- `verify.Result.Actors`: the principals a chain's authority passed through, from the sponsor's grantee to the acting agent.

### Fixed

- At depth 0, `mdt.parent` serialized as the empty string where §5 says there is no parent. A second implementation reading the specification literally would have rejected every chain this one roots - the interop failure §5.1 exists to prevent. Round-tripping through this project's own decoder hid it, so the test now reads the encoded JWS payload. §5.2 also listed neither `iat` nor `aud` as required while V4 and V9 both compare them, and `issue.Sponsor` accepted a grant with no audience, which V9 refuses at every resource server it could be presented to.
- The release workflow published `v0.1.0-rc.1` and `v0.1.0-rc.2` as full releases. `VERSIONING.md` says a pre-release carries no compatibility promise and is not supported, and a release GitHub serves as "Latest" says otherwise whatever the notes say. A tag carrying a SemVer pre-release identifier is now published with `--prerelease`.
- Fuzzing did not run before a release, though the supply-chain document said it did. The release workflow now fuzzes every target on the tag before publishing anything, and the nightly campaign covers `pkg/jose`, which its matrix had omitted.
- An explicitly empty `in` condition did not survive serialization. `encoding/json` drops a zero-length slice under `omitempty` regardless of nil-ness, so "restricts everything" became "no comparison set" — an invalid condition — somewhere between the issuer and the verifier. The §6.1 guarantee that a delegator can always grant nothing on a key was true in memory and false on the wire. `in` no longer carries `omitempty`.
- `condCovers` refused an empty `in` condition under an `eq` or range parent, contradicting the specification's own §6.1 boundary case, which says a delegator can always grant nothing on a key. An empty set matches nothing and is the narrowest restriction expressible, so every parent in the decidable fragment now entails it. The old behaviour failed safe — over-restrictive, never widening — but the specification said otherwise.

### Changed

- The RFC 8693 §4.1 quotation stopped four words short of the clause the argument turns on: the consumer considers the current actor "by the `act` claim", which is the mechanism §3.1 exists to say this project does not use. The Japanese §9.3 rendered a consequence as an obligation.
- The sign-off check failed every Dependabot pull request, which is a required check, so every dependency bump was merged past it. The Developer Certificate of Origin is a statement about a person's right to submit work and a bot cannot make it, so the bot is exempted by actor rather than the check being loosened for everyone. A required check that is routinely overridden is not a check, and the habit it builds is the risk.
- An audit of every external claim in the repository against its primary source. The CSA statistic combined numbers from two 2026 reports under the title of a third, and narrowed the source's "a human or system" to "a human sponsor". MCP does not declare per-tool authorization, agent identity, delegation and consent out of scope - its authorization specification says what it covers and stops, and its auth interest group has active work on two of the four. The Enterprise-Managed Authorization extension states no limit on itself, which four sentences here claimed it did. The EU AI Act's high-risk obligations moved to 2027-12-02 six weeks before this repository last called them applicable, and Article 12 requires neither immutability nor delegation chains. Biscuit evaluates policy in the authorizer, not the token. Three claims cited the COAZ-MCP binding for text it does not contain, including one taken from an open issue comment and described as a resolution.
- The documents described a CI pipeline that is not the one running. `make verify` is seven of the twenty-six checks a pull request runs, not "the same set of checks that gate the merge"; the stated Go version contradicted `go.mod`; the stated requirements were not enough to run the command they preceded; and the source archive was described as built from a signed tag, when neither tag is signed.
- The alternatives analysis covers the OAuth Actor Profile drafts, which are the closest standards work to a Mandatum chain and had been missed entirely. `draft-mcguinness-oauth-actor-profile` gives a resource server processing rules for identifying the current actor, and says in its own words that it does not provide independent cryptographic provenance per hop; the companion `draft-mcguinness-oauth-actor-proofs` adds that, and still does not prove authority did not widen. It also corrects a claim that `modelcontextprotocol/ext-auth#14` had gone unanswered by maintainers, which was wrong when written and survived in two files rather than one.
- CI refuses a document that references a document which does not exist, unless it is declared unwritten in the Planned table. The same defect appeared three times, each found by reading; whoever writes a sentence claiming something is recorded in another file intends to write that file, which is why they never notice it is missing. Links are held to the stricter standard and must resolve even to a Planned document, since a reader who clicks one gets a dead end whatever the table says. The inverse is checked too: an entry still listed as Planned after the document exists misleads a reader the other way.
- The documents described RFC 8693 as silent on what a resource server should do with a delegation chain. It is not: §4.1 requires a consumer to consider only the current actor and treats prior actors in nested `act` claims as informational. Corrected in the specification, the alternatives analysis and both READMEs, along with the consequence, which is that authorizing on a delegation history at the resource server is an extension of the RFC 8693 model rather than a gap in it. This project is that extension, not a reinterpretation of `act`. Corrected by @arjun2075 in openid/authzen#612.
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
