# Threat model

Last reconciled with the implementation: 2026-09-17. That is when what follows was last checked against the code, which is the claim a reader needs from a threat model and the one that goes stale without anything looking wrong; `git log` holds the edit history. Covers the Delegation Assertion format, the verifier, the signing layer, the AuthZEN binding, sequence evaluation, revocation sets and the MCP enforcement point, at the state described in [CHANGELOG.md](../../CHANGELOG.md).

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
5. **The trust bundle is correct.** Whoever populates it decides which issuers exist. A wrong entry is a forged chain that verifies. Where keys are pinned with `jose.KeyRing` that is the operator. Where they are fetched with `jose.JWKS` it is the operator's choice of URL *and* everything that stands between the verifier and it: the TLS chain, DNS, and whoever can write to that endpoint. Fetching narrows nothing and widens the trusted set — it buys rotation without a flag day and pays for it in one more thing that has to be right.
6. **The PDP is not trusted to grant, if the enforcement point does its part.** It may deny anything. Bounding what it can allow is not automatic and does not follow from verification: nothing in an evaluation response is constrained by the chain. The bound exists only where the PEP also calls `Result.Permits` with the request it is about to honour and refuses on its failure regardless of the PDP's answer. A PEP that verifies the chain and then does whatever the PDP says has given the PDP the sponsor's authority. `pkg/mcp` is an enforcement point that does this part, in the order specification §8 requires; a deployment using it inherits the bound rather than having to assemble it, and one calling `verify.Verify` directly still has to.

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

A chain issued for one resource server is presented to another, or an agent's broad connectivity substitutes for its caller's narrower authority. Answered by §6 rule 7, which fixes the audience for the whole chain, by V9, which compares the leaf's audience to the verifier, and by V2 (a delegator may only delegate what it holds, so the chain records which principal actually caused the action rather than only which one presented it).

V9 alone was not enough, and for a while that is all there was. An agent holding a valid chain could sign a further link naming a different resource server — same capabilities, itself as delegator, so every other rule held — and present it there, where V9 compared the leaf's audience against that server and passed. Rule 7 is what closes it; without it the audience is chosen by whoever issues the leaf, which in this threat is the compromised agent.

### Sequence evasion

An agent reads untrusted content and then mutates, which per-call authorization cannot see. Answered by sequence constraints, evaluated per chain root so that delegating to a fresh sub-agent lands in the same history. An unreadable history denies.

Three residual weaknesses, each of which makes the constraint weaker than it looks:

- **A constraint is only as good as the tags.** The rules match on resource tags, so a mutating tool nobody tagged `mutating` is unconstrained. Nothing here can verify that a deployment tagged its tools honestly, and a missing tag fails open in the sense that matters: the action is admitted.
- **One store, one enforcement point.** The shipped store is in-process. Two PEPs with separate stores give an agent two histories to spend, which defeats a constraint rather than weakening it. A deployment with more than one enforcement point does not have sequence constraints today.
- **`Forget` resets.** Discarding a chain's history clears the triggers it is under. It exists for chains that have expired, and calling it on a live one is a way past a constraint. The store refuses to grow past a cap rather than evicting, for exactly this reason, but the explicit call is still there for a caller to misuse.

### Log tampering

An attacker with write access edits or removes audit records. Answered by an RFC 6962-style Merkle tree with inclusion and consistency proofs. **Not yet implemented.**

### Denial of service

Malformed input at the enforcement point. Parsing and chain verification are fuzzed continuously; a panic there would deny every protected call, so it is treated as a security defect rather than a robustness one. Chain length is bounded by the sponsor's depth budget, and sequence state is fixed-size by construction, so neither grows with attacker input.

A panic is not the only shape this takes, and assuming it was is how the one instance of this got shipped. A published revocation set declares how many hash positions a lookup checks, and that number had no upper bound: eighty bytes declaring *k* in the billions made a single `MayContain` take three seconds and ask for fourteen gigabytes, on the path of every authorized action. No crash, no malformed input in the parser's sense — a well-formed document whose declared parameters chose the cost of enforcement. §7.1 now bounds *k* at 64 and `revoke.ParseSet` refuses a set outside it, with the refusal made before anything proportional to the declared value. The general rule it came from: a number in an input that a loop runs on is a bound the input's author gets to pick, and every such number in the wire format needs one of ours.

That defect was found by a fuzz campaign against `pkg/revoke`, a target which sat in the repository for twenty-one hours without being in the nightly matrix — from the commit that added it to the commit that fixed the matrix — and which produced a crasher one hour and fifty minutes into the first campaign that ran it. The lesson recorded here is not about the bound but about the coverage: a fuzz target nothing runs is a test suite entry that reads as assurance, and the interval that matters is not how long it went unrun but how short the run was that found something.

Residual: signature verification costs one Ed25519 check per link. A verifier facing untrusted volume needs rate limiting above it, which this project does not provide.

Residual: the bounds are on what a document may declare, not on how often it may be presented. A caller that presents the longest permitted chain, with the largest permitted capability set, as fast as it can still costs more than a caller that does not.

## Not yet covered

Listed because a threat model that only describes finished work is a marketing document.

| Gap | Consequence |
| --- | --- |
| No replicated sequence store | The shipped store is in-process. A deployment with more than one enforcement point has no sequence constraints, whatever its assertions declare. |
| Sequence rules depend on resource tags nothing verifies | An untagged mutating tool is unconstrained. The trust boundary here is whoever tags the tools. |
| No audit log | There is no tamper-evident record. The attribution the format establishes is not yet written anywhere durable, and §10 of the specification describes something that does not exist. |
| No revocation publisher | `pkg/revoke` builds, publishes and evaluates the compact set of §7.1, so a PEP answers V8 locally. What no code here does is republish one on a schedule or serve it, so a deployment supplies both. A set that stops being republished eventually denies everything rather than quietly enforcing nothing, which is the right failure and still an outage. |
| Untested against a real PDP | The AuthZEN client is exercised against test servers covering each failure mode, not against any implementation somebody else wrote. |
| No third-party review | Everything here is the authors' own analysis of their own design. Treat it accordingly. |
| Key compromise is undetectable | No monitoring, no transparency log for issued assertions. |
| Cross-trust-domain chains are unspecified | SPIFFE federation answers key resolution; who may sponsor across a domain boundary is open. See specification section 12. |

## Assumptions a deployment must check itself

- Assertion lifetimes are short enough that the revocation lag is acceptable.
- The trust bundle contains only issuers that should be able to mint authority.
- Agents cannot read each other's private keys. Mandatum bounds what a compromised agent can *delegate*; it cannot stop one that has stolen another's key from *being* it.
- The sponsor authority is not the same system as the agents it issues for.
- If keys are fetched rather than pinned, the cache TTL is short enough. A key removed from an issuer's document stays usable at a verifier until its copy expires, so the TTL is the window in which a retired key still verifies. The default is five minutes; a deployment that sets it long has chosen that window.
- If revocation is evaluated from a compact set, something publishes a new one. The set records when it was built and the checker refuses to answer from one older than its maximum age, so a publisher that stops publishing eventually denies everything rather than quietly enforcing nothing — but the denial is an outage, and nothing in this repository schedules the publishing.
- Every enforcement point calls `Result.Permits` for the request it is about to perform, and treats its failure as a denial. Verification says who delegated what; only this call says the thing being asked for is inside it. A deployment that skips it inherits assumption 6's failure mode in full. `pkg/mcp.Enforcer` makes the call for MCP tool calls, so a deployment behind it is checking this; the assumption is one a deployment wiring the packages together itself has to check.
- The tags a deployment attaches to its tools describe what those tools do. `pkg/mcp` refuses a tool its catalog does not describe, which stops an unknown tool from satisfying every tag-matching constraint written to stop it — but a tool tagged wrongly is worse than one tagged not at all, and nothing here can check a tag against what the tool actually does.

## Reporting

Anything here that is wrong, and anything not here that should be, goes through [SECURITY.md](../../SECURITY.md). A report that the threat model is incomplete is in scope and welcome.
