# Governance

This document describes how the Mandatum project is governed. It is the authoritative source; where any other document disagrees, this one wins.

Mandatum is an independent open source project. It is not controlled by any company, and no company holds a special position in its decision making. The mechanisms in §5 exist to keep that true as the project grows rather than to merely assert it.

## 1. Roles

Mandatum uses a four-rung contributor ladder. Every rung has explicit entry criteria, explicit responsibilities, and an explicit path to the next rung.

| Role | Entry | Responsibilities | Rights |
| --- | --- | --- | --- |
| Contributor | Any accepted contribution (code, docs, review, triage, a reproducible bug report). | Follow the Code of Conduct. | Listed in release notes. |
| Reviewer | Nominated by a Maintainer after sustained, high-quality review activity. Lazy consensus of Maintainers. | Review pull requests in a declared area. | `/lgtm` authority; non-binding on merge. |
| Approver | Nominated by a Maintainer after sustained Reviewer work and demonstrated judgment in a declared area. Lazy consensus of Maintainers. | Approve and merge within a declared area. | Merge authority in that area. |
| Maintainer | Nominated by a Maintainer, requires supermajority of Maintainers (§4). | Project direction, releases, security response, governance. | Binding vote. |

"Declared area" means a directory or subsystem, recorded in `OWNERS` files.

Emeritus is a fifth, non-voting status recording past Maintainers who have stepped down in good standing. Emeritus Maintainers keep their entry in `MAINTAINERS.md` under a separate heading and may be restored by lazy consensus without a new nomination.

## 2. Maintainer lifecycle

The project treats maintainer turnover as normal and expected, not as a failure. Both directions of this process must be exercised in practice, not only documented.

### 2.1 Becoming a Maintainer

1. An existing Maintainer opens a public nomination issue describing the nominee's contributions over at least the preceding three months.
2. A comment period of at least seven days.
3. A supermajority vote of current Maintainers (§4), recorded in the issue.
4. On success, the nominee is added to `MAINTAINERS.md` in the same pull request that closes the nomination issue.

### 2.2 Stepping down

A Maintainer may step down at any time by opening a pull request moving their entry to Emeritus. No vote is required.

### 2.3 Inactivity

A Maintainer with no substantive project activity for six months is contacted privately. If there is no response within thirty days, a pull request moves them to Emeritus. This is administrative, not disciplinary, and carries no implication of fault. Restoration requires only a pull request.

### 2.4 Removal for cause

Removal for a Code of Conduct violation or for acting against the project's interest requires a supermajority of Maintainers excluding the subject, after a private discussion in which the subject is given the opportunity to respond.

### 2.5 Affiliation changes

A Maintainer whose employment changes MUST update the Company column of `MAINTAINERS.md` within thirty days. This is a governance obligation because the organizational balance rules in §5 are computed from that column, and stale affiliations would silently defeat them.

## 3. Decision making

Most decisions are made by **lazy consensus**: a proposal is made publicly, and if no Maintainer objects within the comment period, it carries. Anyone may raise a concern; only a Maintainer can block.

| Decision | Mechanism | Comment period |
| --- | --- | --- |
| Routine change | Approver review, lazy consensus | none |
| New Reviewer or Approver | Lazy consensus of Maintainers | 3 days |
| Roadmap change, new subproject | Lazy consensus of Maintainers | 7 days |
| New Maintainer, removal, governance change | Supermajority vote (§4) | 7 days |
| Security embargo handling | Security Response Team, see `SECURITY.md` | none |

When lazy consensus fails, the matter escalates to a vote. Votes happen in public issues except where `SECURITY.md` or §2.4 requires privacy.

## 4. Voting

A supermajority is **two thirds of eligible Maintainer votes cast**, subject to the organizational cap in §5.2, with a quorum of half the Maintainers.

Votes are recorded as `+1`, `0`, or `-1` in the relevant issue. A `-1` must be accompanied by a rationale and, where applicable, a description of what would change the vote. A `-1` without rationale is counted as `0`.

## 5. Organizational balance

CNCF requires an organizational-balance mechanism at Graduation. Mandatum adopts one from the start, because retrofitting governance onto an established project is materially harder than beginning with it, and because a project's neutrality claim should be structural rather than aspirational.

### 5.1 Affiliation

A Maintainer's organization is their employer, as recorded in `MAINTAINERS.md`. Membership of a GitHub organization does not constitute affiliation. Maintainers employed by the same parent company, or by entities under common control, count as one organization.

### 5.2 Voting cap

**No single organization may cast more than one third of the votes counted on any matter requiring a supermajority.** If an organization holds more than one third of Maintainer seats, its votes are proportionally down-weighted to one third. Down-weighting is applied before the supermajority threshold is computed, and the calculation is recorded in the vote's issue.

This cap binds regardless of how many seats an organization holds, so a project that becomes single-vendor in staffing does not thereby become single-vendor in control.

### 5.3 Single-organization periods

Until Mandatum has Maintainers from at least two organizations, §5.2 has no effect and the project is, in fact, single-organization. The project states this plainly here rather than obscuring it, and treats recruiting Maintainers from a second organization as a release-blocking goal for v1.0 (see `ROADMAP.md`).

### 5.4 Infrastructure neutrality

Project infrastructure must not be owned by an individual or a company in a way that could be used as leverage. The following are held by the project and listed with their current custodian in `docs/project/infrastructure.md`:

- the source repositories and their organization
- the domain name and DNS
- CI/CD configuration and any self-hosted runners
- release signing keys and the transparency log entries they produce
- container image registries and the `maintainer` label on published images
- the project's social and communication accounts

On donation to a foundation, all of the above transfer with the project.

## 6. Vendor neutrality

- No feature is accepted whose purpose is to advantage one commercial product.
- Documentation does not recommend a commercial offering over an equivalent open source one, and comparisons cite verifiable evidence.
- Integrations are held to one standard regardless of who maintains the other side. Mandatum integrates with any AuthZEN-conformant PDP; it does not privilege one engine, and the conformance tests are the same for all.
- Maintainers act in the project's interest. Where a Maintainer's employer has a material interest in a decision, the Maintainer discloses it in the thread before voting.

## 7. Changing this document

Governance changes follow §3: a public pull request, a seven-day comment period, and a supermajority vote subject to §5.2. The pull request must state what problem the change solves.
