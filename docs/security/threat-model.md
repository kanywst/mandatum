# Threat model

Last updated: 2026-09-12. Covers the Delegation Assertion format and the verifier, at the state described in [CHANGELOG.md](../../CHANGELOG.md).

The specification carries a summary table in section 11. This is the full version: what is being defended, from whom, what is assumed rather than enforced, and what is knowingly not covered.

## What is being protected

One property, stated as narrowly as it can be:

> **An agent can exercise only authority some named human granted, narrowed at every hop, and every exercise is attributable to that human and revocable without affecting anyone else.**

Everything below is about ways that sentence could be false.

## Assets

| Asset | Why an attacker wants it |
| --- | --- |
| A signing key | Mints authority. An issuer's key forges any delegation below it; the sponsor authority's key forges whole chains. |
| A valid chain | Bearer authority up to its capability set until it expires or is revoked. |
| The revocation set | Suppressing a revocation keeps a killed chain alive. |
| Sequence state | Losing or resetting it re-enables an action a constraint had forbidden. |
| The audit log | Rewriting it removes the record of what was done and by whom. |

## Actors

- **A network attacker** who can read, drop, delay and replay traffic, but holds no key.
- **A compromised agent** that legitimately holds a chain and its own signing key, and wants more authority than it was given. This is the actor the format exists for.
- **A compromised PDP** that answers evaluation requests dishonestly.
- **A malicious issuer** — an agent that delegates, acting against a sub-agent or against the sponsor.
- **A curious insider** who can read stored assertions and logs.

Out of scope as actors: anyone holding the sponsor authority's signing key, and anyone with code execution inside a verifier. Both are game over by construction, and pretending otherwise would be theatre.

## Trust assumptions

Stated plainly, because an unstated assumption is how a threat model becomes wrong without anyone noticing.

1. **Ed25519 and SHA-256 hold.** Signature forgery and second-preimage attacks are out of scope.
2. **The sponsor authority authenticated the human.** Mandatum records `amr` and `auth_time` for policy to inspect; it does not verify them. A lying identity provider produces chains rooted in a fiction.
3. **Private keys stay private.** There is no key-compromise detection. Revocation is the recovery path, and it is only as fast as whoever notices.
4. **Verifier clocks are roughly right.** Skew is bounded to five minutes; beyond that, expiry is unreliable in whichever direction the clock is wrong.
5. **The trust bundle is correct.** Whoever populates it decides which issuers exist. A wrong entry is a forged chain that verifies.
6. **The PDP is not trusted to grant.** It may deny anything and may allow only within the chain's capability set. This is enforced by ordering: verification runs first and bounds what a decision can mean.

## Threats and what answers them

### Forging a delegation

An attacker mints an assertion claiming an issuer they do not control. Answered by V3: every link's signature is checked against a key resolved for the issuer the *chain* names, never one nominated inside the token. `pkg/jose` accepts exactly one algorithm, so `alg: none` and HMAC key-confusion have no code path, and an unknown header parameter is refused rather than ignored.

### Splicing

An attacker assembles a chain out of links that were never issued against each other — for example attaching a broad grant's child to a different root. Answered by V1: every link commits to the digest of its parent's exact bytes, so links are not interchangeable. The digest covers the serialization as received, not a re-encoding, so two spellings of the same claims cannot collide.

### Escalation by sub-delegation

The actor this format is for. A compromised agent holds a real chain and its own key, and issues itself a child with more authority. Answered by V5 and section 6: capabilities may only narrow, expiry may only shorten, the depth budget may only fall, and sequence constraints may only tighten. Undecidable comparisons answer "does not narrow".

The rules are enforced at verification, not only at issuance. `pkg/issue` applies the same check before signing, but that is ergonomics — it puts the error where someone can fix it. Security rests on the verifier, and both call one implementation so they cannot drift.

### Stripping attribution

An agent rewrites `mdt.root` to point at a different human, or drops it, so its actions are attributed elsewhere. Answered by V6: the sponsor is byte-identical across every link, and a link whose copy differs fails. Because `root` is inside the signed payload, changing it invalidates the signature as well.

### Replay after revocation

A revoked chain is presented again. Answered by V8. An unanswerable revocation check denies rather than allowing, so an attacker who can only break the revocation service gets denials, not a bypass. Revoking any link kills its descendants, since they commit to it.

Residual: revocation is only as fresh as its distribution. A chain revoked one second ago may verify at a PEP whose set is a minute old. Short lifetimes are the mitigation, and choosing them is a deployment decision the format cannot make.

### Confused deputy

A chain issued for one resource server is presented to another, or an agent's broad connectivity substitutes for its caller's narrower authority. Answered by V9 (the leaf names the audience) and V2 (a delegator may only delegate what it holds, so the chain records which principal actually caused the action rather than only which one presented it).

### Sequence evasion

An agent reads untrusted content and then mutates, which per-call authorization cannot see. Answered by sequence constraints — **and this is the part not yet implemented**. See "Not yet covered".

### Log tampering

An attacker with write access edits or removes audit records. Answered by an RFC 6962-style Merkle tree with inclusion and consistency proofs. **Not yet implemented.**

### Denial of service

Malformed input at the enforcement point. Parsing and chain verification are fuzzed continuously; a panic there would deny every protected call, so it is treated as a security defect rather than a robustness one. Chain length is bounded by the sponsor's depth budget, and sequence state is fixed-size by construction, so neither grows with attacker input.

Residual: signature verification costs one Ed25519 check per link. A verifier facing untrusted volume needs rate limiting above it, which this project does not provide.

## Not yet covered

Listed because a threat model that only describes finished work is a marketing document.

| Gap | Consequence |
| --- | --- |
| Sequence evaluation is not implemented | The read-then-mutate pattern is expressible and attenuated, but nothing enforces it. Do not rely on `mdt.seq` today. |
| No audit log | There is no tamper-evident record. The attribution the format establishes is not yet written anywhere durable. |
| No revocation distribution | `RevocationChecker` is an interface with no production implementation. |
| No AuthZEN binding | Nothing turns a verified chain into an evaluation request yet. |
| No third-party review | Everything here is the authors' own analysis of their own design. Treat it accordingly. |
| Key compromise is undetectable | No monitoring, no transparency log for issued assertions. |
| Cross-trust-domain chains are unspecified | SPIFFE federation answers key resolution; who may sponsor across a domain boundary is open. See specification section 12. |

## Assumptions a deployment must check itself

- Assertion lifetimes are short enough that the revocation lag is acceptable.
- The trust bundle contains only issuers that should be able to mint authority.
- Agents cannot read each other's private keys. Mandatum bounds what a compromised agent can *delegate*; it cannot stop one that has stolen another's key from *being* it.
- The sponsor authority is not the same system as the agents it issues for.

## Reporting

Anything here that is wrong, and anything not here that should be, goes through [SECURITY.md](../../SECURITY.md). A report that the threat model is incomplete is in scope and welcome.
