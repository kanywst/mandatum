// Package mcp enforces a Mandatum delegation chain on an MCP tool call.
//
// Everything else in this repository establishes facts. This package is the
// one place that acts on them, which makes it the only place where an
// ordering mistake grants authority nobody delegated. Specification §8 sets
// that ordering out, and Authorize is it:
//
//  1. verify the chain (§7, rules V1 through V9);
//  2. check the chain's own capability set covers the call (§8, step 2);
//  3. ask the Policy Decision Point (§8, step 3);
//  4. admit the action against the chain's history (§9).
//
// The call proceeds only if all four agree. Step 2 is the one a PEP is most
// likely to skip, because the PDP has already said yes by the time it feels
// redundant; skipping it hands the PDP the sponsor's authority, and every
// other property this project has follows from not doing that.
//
// Step 4 runs last, after the PDP has allowed, because admitting an action
// both decides and records it. A call the PDP refused never happened, and
// counting it against the chain's invocation budget would let anything that
// can provoke a denial spend a sponsor's budget to zero.
//
// Everything here fails closed. A tool the deployment cannot describe, a
// chain that does not parse, a PDP that cannot be reached, a sequence store
// that cannot be read — each denies, and each names which of the four steps
// refused so that an operator is not left guessing.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kanywst/mandatum/pkg/authzen"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/sequence"
	"github.com/kanywst/mandatum/pkg/verify"
)

// Decider is the Policy Decision Point. *authzen.Client satisfies it.
//
// It is an interface so that a deployment can put its own transport,
// caching or fan-out in front of a PDP without this package knowing. An
// implementation that cannot reach its PDP must return an error; returning
// an allow on failure is the one thing it must never do.
type Decider interface {
	Evaluate(ctx context.Context, r authzen.Request) (authzen.Decision, error)
}

// Facts are what a deployment knows about one of its tools that the protocol
// does not say and the chain cannot.
//
// MCP describes a tool by name and input schema. Nothing in it says whether a
// tool reads attacker-controlled text or writes to a system of record, and
// that distinction is what a sequence constraint is written against. It has
// to come from the deployment.
type Facts struct {
	// Tags classify the resource: "external-content" for something an agent
	// should not trust, "mutating" for something that changes state. A
	// capability requiring a tag matches only a resource carrying it, and a
	// sequence constraint matching on tags is only as good as these are.
	Tags []string
	// Attributes are the values a capability's conditions are evaluated
	// against, keyed by the names the conditions use. Nothing here derives
	// them from the tool's arguments: a condition on "args.index" and an
	// argument named "index" look like an obvious pairing, and guessing at
	// it is how a condition silently ends up matching the wrong value.
	Attributes map[string]any
}

// Catalog describes the tools a server exposes.
//
// Describe is called for every tool call, before the chain is compared
// against it. A tool the catalog does not know is a denial rather than a
// tool with no tags: an unknown tool with no tags satisfies every
// tag-matching constraint written to stop it, so the safe reading of "I have
// never heard of this" is no.
type Catalog interface {
	Describe(tool string, arguments map[string]any) (Facts, error)
}

// CatalogFunc adapts a function to Catalog.
type CatalogFunc func(tool string, arguments map[string]any) (Facts, error)

// Describe calls f.
func (f CatalogFunc) Describe(tool string, arguments map[string]any) (Facts, error) {
	return f(tool, arguments)
}

// Tools is a static Catalog mapping each tool name to its tags.
//
// It covers the common deployment, where what a tool does is a property of
// the tool rather than of its arguments. It supplies no attributes, so a
// chain carrying a capability conditioned on one will be refused under this
// catalog — correctly, since nothing here can report a value it was never
// told. Use CatalogFunc where conditions are in play.
type Tools map[string][]string

// Describe returns the tags registered for tool, or an error if there are none.
func (t Tools) Describe(tool string, _ map[string]any) (Facts, error) {
	tags, ok := t[tool]
	if !ok {
		return Facts{}, fmt.Errorf(
			"mcp: %q is not a tool this catalog describes, so what it does is unknown", tool)
	}
	return Facts{Tags: tags}, nil
}

// Stage names the check that refused a call.
type Stage string

// The stages, in the order Authorize runs them.
const (
	// StageVerify is chain verification: rules V1 through V9.
	StageVerify Stage = "verify"
	// StageCatalog is the deployment's description of the tool.
	StageCatalog Stage = "catalog"
	// StagePermits is the chain's own capability set.
	StagePermits Stage = "permits"
	// StagePolicy is the Policy Decision Point.
	StagePolicy Stage = "policy"
	// StageSequence is the chain's action history.
	StageSequence Stage = "sequence"
)

// Refusal is a call that was not authorized, and which check refused it.
//
// The stage is the operationally useful half: "the PDP said no" and "the
// sponsor never granted this" look identical to a caller and mean entirely
// different things to whoever is on call.
type Refusal struct {
	// Stage is the check that refused.
	Stage Stage
	// Err is why, in that check's own terms.
	Err error
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("mcp: refused at %s: %v", r.Stage, r.Err)
}

// Unwrap exposes the underlying error, so that a caller can reach a
// *sequence.Denial or a rule error with errors.As.
func (r *Refusal) Unwrap() error { return r.Err }

// Refused reports whether err is a *Refusal, and which stage refused.
func Refused(err error) (*Refusal, bool) {
	var r *Refusal
	ok := errors.As(err, &r)
	return r, ok
}

// Default vocabulary for the chain's own capability set.
//
// A capability names a resource type and an action, and those are the
// project's terms rather than AuthZEN's: a grant reads
// `mcp_tool`/`invoke`, while the evaluation request sent to the PDP carries
// the COAZ-MCP binding's `tool` and `tools/call`. The two vocabularies are
// deliberately separate, because a deployment writing grants against its own
// resource model should not have to adopt the binding's.
const (
	DefaultResourceType = "mcp_tool"
	DefaultAction       = "invoke"
)

// Enforcer authorizes tool calls against delegation chains.
type Enforcer struct {
	verifier     *verify.Verifier
	pdp          Decider
	sequences    *sequence.Evaluator
	catalog      Catalog
	server       string
	resourceType string
	action       string

	// Used only by Middleware; see http.go.
	maxBody int64
	log     *slog.Logger
}

// Option configures an Enforcer.
type Option func(*Enforcer)

// WithServer sets the MCP server identifier reported to the PDP in
// `resource.properties.server`, for policy that varies by deployment.
func WithServer(id string) Option {
	return func(e *Enforcer) { e.server = id }
}

// WithGrantVocabulary replaces the resource type and action a chain's
// capabilities are written in. The defaults are DefaultResourceType and
// DefaultAction.
//
// This changes which capabilities match, so it is a security-relevant
// setting rather than a naming preference: a chain granting `invoke` on
// `mcp_tool` permits nothing at an enforcement point configured for some
// other pair, and vice versa.
func WithGrantVocabulary(resourceType, action string) Option {
	return func(e *Enforcer) {
		e.resourceType = resourceType
		e.action = action
	}
}

// New returns an Enforcer.
//
// All four arguments are required, and a nil one is an error rather than a
// disabled check:
//
//   - verifier establishes that the chain is valid at all;
//   - catalog says what the tool being called actually does;
//   - pdp applies organizational policy;
//   - sequences enforces constraints across the chain's history.
//
// An enforcer missing any of them would still authorize calls, while
// silently having dropped one of the four checks §8 and §9 require. That is
// the failure mode this project exists to argue against, so it is refused at
// construction rather than discovered in production.
func New(
	verifier *verify.Verifier,
	catalog Catalog,
	pdp Decider,
	sequences *sequence.Evaluator,
	opts ...Option,
) (*Enforcer, error) {
	switch {
	case verifier == nil:
		return nil, errors.New("mcp: a Verifier is required; an enforcer that does not check chains authorizes forgeries")
	case catalog == nil:
		return nil, errors.New("mcp: a Catalog is required; an enforcer that cannot describe a tool cannot apply a constraint about what tools do")
	case pdp == nil:
		return nil, errors.New("mcp: a Decider is required; use one that denies if this deployment has no PDP")
	case sequences == nil:
		return nil, errors.New("mcp: a sequence Evaluator is required; without one a chain's constraints are carried and never enforced")
	}

	e := &Enforcer{
		verifier:     verifier,
		catalog:      catalog,
		pdp:          pdp,
		sequences:    sequences,
		resourceType: DefaultResourceType,
		action:       DefaultAction,
	}
	for _, o := range opts {
		o(e)
	}
	if e.resourceType == "" || e.action == "" {
		return nil, errors.New("mcp: the grant vocabulary needs both a resource type and an action; an empty one matches no capability")
	}
	return e, nil
}

// Call is one `tools/call` request, with the chain presented alongside it.
type Call struct {
	// Chain is the delegation chain, sponsor's grant first. It is untrusted
	// until Authorize returns.
	Chain mda.Chain
	// Tool is `params.name`.
	Tool string
	// Arguments are `params.arguments`.
	Arguments map[string]any
}

// Authorized is what a permitted call established.
type Authorized struct {
	// Chain is the verified chain: who sponsored this, which agents the
	// authority passed through, and the digest identifying it in an audit
	// record.
	Chain *verify.Result
	// Decision is the PDP's answer, including whatever context it chose to
	// explain itself with. It is always an allow — a deny is a *Refusal.
	Decision authzen.Decision
}

// Authorize runs the four checks in order and returns nil only if all agree.
//
// A non-nil error denies the call. It is a *Refusal naming the stage;
// callers wanting to distinguish "your chain does not permit this" from "the
// PDP is unreachable" should read the stage rather than the message.
func (e *Enforcer) Authorize(ctx context.Context, call Call) (*Authorized, error) {
	if call.Tool == "" {
		return nil, &Refusal{Stage: StageCatalog, Err: errors.New("the request names no tool")}
	}

	// 1. The chain, against every rule in §7. Nothing below may run on a
	//    chain that did not pass this, which is why it is first and why a
	//    partial result is not returned on failure.
	verified, err := e.verifier.Verify(ctx, call.Chain)
	if err != nil {
		return nil, &Refusal{Stage: StageVerify, Err: err}
	}

	// 2a. What this tool is. It comes before the capability check because
	//     the capability check compares against the tool's tags.
	facts, err := e.catalog.Describe(call.Tool, call.Arguments)
	if err != nil {
		return nil, &Refusal{Stage: StageCatalog, Err: err}
	}

	// 2b. The chain's own grant. This is §8 step 2, the bound on what any
	//     later answer can mean.
	if err := verified.Permits(verify.Request{
		ResourceType: e.resourceType,
		ResourceID:   call.Tool,
		ResourceTags: facts.Tags,
		Action:       e.action,
		Attributes:   facts.Attributes,
	}); err != nil {
		return nil, &Refusal{Stage: StagePermits, Err: err}
	}

	// 3. Organizational policy, on top of what the sponsor delegated. The
	//    PDP can narrow what the chain allows and cannot widen it, because
	//    step 2 already ran and refused anything outside the grant.
	decision, err := e.pdp.Evaluate(ctx, authzen.ToolCallRequest(verified, authzen.ToolCall{
		Name:      call.Tool,
		Arguments: call.Arguments,
		Server:    e.server,
	}))
	if err != nil {
		return nil, &Refusal{Stage: StagePolicy, Err: err}
	}
	if !decision.Allowed {
		return nil, &Refusal{Stage: StagePolicy, Err: errors.New("the policy decision point denied this call")}
	}

	// 4. The history, which is the part no per-call check can do. Last,
	//    because admitting is also recording: see the package comment.
	if err := e.sequences.Admit(ctx, verified.RootID, verified.Sequence, sequence.Action{
		Name:         e.action,
		ResourceType: e.resourceType,
		ResourceTags: facts.Tags,
	}); err != nil {
		return nil, &Refusal{Stage: StageSequence, Err: err}
	}

	return &Authorized{Chain: verified, Decision: decision}, nil
}
