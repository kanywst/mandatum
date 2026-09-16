package mcp_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/kanywst/mandatum/pkg/authzen"
	"github.com/kanywst/mandatum/pkg/issue"
	"github.com/kanywst/mandatum/pkg/jose"
	"github.com/kanywst/mandatum/pkg/mcp"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/sequence"
	"github.com/kanywst/mandatum/pkg/verify"
)

// These tests run against real Ed25519 keys and real signatures, because the
// thing under test is an ordering of checks and a stubbed verifier would let
// a wrong order pass.

const (
	idp      = "https://idp.example.org"
	audience = "https://mcp.example.org"
	agentA   = "spiffe://example.org/ns/agents/planner"
	agentB   = "spiffe://example.org/ns/agents/retriever"
)

type world struct {
	t     *testing.T
	ring  *jose.KeyRing
	idp   issue.Signer
	a     issue.Signer
	now   time.Time
	spons mda.Sponsor
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{
		t:    t,
		ring: jose.NewKeyRing(),
		now:  time.Unix(1789200000, 0),
		spons: mda.Sponsor{
			Issuer:                idp,
			Subject:               "u-8f31c02e",
			AuthenticationMethods: []string{"pwd", "hwk"},
			AuthenticatedAt:       1789199400,
		},
	}
	w.idp = w.keypair(idp, "idp-2026")
	w.a = w.keypair(agentA, "a-1")
	return w
}

func (w *world) keypair(id, kid string) issue.Signer {
	w.t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.ring.Add(id, kid, pub); err != nil {
		w.t.Fatal(err)
	}
	return issue.Signer{ID: id, KeyID: kid, Key: priv}
}

func (w *world) verifier() *verify.Verifier {
	w.t.Helper()
	v, err := verify.New(w.ring, noRevocations{}, audience,
		verify.WithClock(func() time.Time { return w.now.Add(time.Minute) }))
	if err != nil {
		w.t.Fatal(err)
	}
	return v
}

// chain issues a sponsor grant over search.* and a sub-delegation narrowing
// it to search.query, optionally carrying sequence constraints.
func (w *world) chain(seq *mda.Sequence) mda.Chain {
	w.t.Helper()

	root, err := issue.Sponsor(w.idp, w.spons, issue.Grant{
		Subject:      agentA,
		Audience:     audience,
		ID:           "jti-root",
		Lifetime:     time.Hour,
		IssuedAt:     w.now,
		MaxDepth:     issue.Depth(3),
		Capabilities: []mda.Capability{capability("search.*")},
		Sequence:     seq,
	})
	if err != nil {
		w.t.Fatalf("sponsor grant: %v", err)
	}
	return mda.Chain{root}
}

func capability(id string) mda.Capability {
	return mda.Capability{
		Resource: mda.ResourcePattern{Type: "mcp_tool", ID: id},
		Action:   mda.ActionPattern{Name: "invoke"},
	}
}

type noRevocations struct{}

func (noRevocations) IsRevoked(context.Context, string) (bool, error) { return false, nil }

// pdp records what it was asked and answers as configured.
type pdp struct {
	allow   bool
	err     error
	asked   int
	lastReq authzen.Request
}

func (p *pdp) Evaluate(_ context.Context, r authzen.Request) (authzen.Decision, error) {
	p.asked++
	p.lastReq = r
	if p.err != nil {
		return authzen.Deny, p.err
	}
	return authzen.Decision{Allowed: p.allow}, nil
}

// catalog covers the tools these tests call.
var catalog = mcp.Tools{
	"search.query":  {},
	"search.fetch":  {"external-content"},
	"search.write":  {"mutating"},
	"admin.wipeAll": {},
}

func enforcer(t *testing.T, w *world, decider mcp.Decider, store sequence.Store) *mcp.Enforcer {
	t.Helper()
	if store == nil {
		store = sequence.NewMemoryStore()
	}
	evaluator, err := sequence.NewEvaluator(store)
	if err != nil {
		t.Fatal(err)
	}
	e, err := mcp.New(w.verifier(), catalog, decider, evaluator, mcp.WithServer(audience))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func stageOf(t *testing.T, err error) mcp.Stage {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got none")
	}
	refusal, ok := mcp.Refused(err)
	if !ok {
		t.Fatalf("expected a *mcp.Refusal, got %T: %v", err, err)
	}
	return refusal.Stage
}

func TestAuthorizeAllowsACallEverythingAgreesOn(t *testing.T) {
	w := newWorld(t)
	decider := &pdp{allow: true}
	e := enforcer(t, w, decider, nil)

	got, err := e.Authorize(context.Background(), mcp.Call{
		Chain: w.chain(nil),
		Tool:  "search.query",
	})
	if err != nil {
		t.Fatalf("expected an allow: %v", err)
	}
	if got.Chain.Sponsor.Subject != w.spons.Subject {
		t.Errorf("sponsor = %q, want %q", got.Chain.Sponsor.Subject, w.spons.Subject)
	}
	// The request handed to the PDP is the COAZ-MCP mapping, which
	// pkg/authzen tests in detail. What matters here is that the enforcer
	// passed the verified chain rather than assembling one of its own.
	if decider.lastReq.Subject.ID != w.spons.Subject {
		t.Errorf("subject.id = %q, want the sponsor", decider.lastReq.Subject.ID)
	}
	if decider.lastReq.Resource.ID != "search.query" {
		t.Errorf("resource.id = %q, want the tool", decider.lastReq.Resource.ID)
	}
}

// The test this package exists for. A PDP that says yes to everything must
// not be able to authorize a tool the sponsor never granted, and the PDP must
// not even be asked: §8 orders the capability check before the evaluation so
// that a compromised PDP never sees a request it could widen.
func TestAPermissivePDPCannotWidenTheGrant(t *testing.T) {
	w := newWorld(t)
	decider := &pdp{allow: true}
	e := enforcer(t, w, decider, nil)

	_, err := e.Authorize(context.Background(), mcp.Call{
		Chain: w.chain(nil),
		Tool:  "admin.wipeAll",
	})
	if stage := stageOf(t, err); stage != mcp.StagePermits {
		t.Errorf("refused at %q, want %q", stage, mcp.StagePermits)
	}
	if decider.asked != 0 {
		t.Errorf("the PDP was asked %d times about a call outside the grant; it must not be asked at all", decider.asked)
	}
}

func TestAnInvalidChainIsRefusedBeforeAnythingElse(t *testing.T) {
	w := newWorld(t)
	decider := &pdp{allow: true}
	e := enforcer(t, w, decider, nil)

	chain := w.chain(nil)
	// One flipped byte in the signed serialization. Every later check would
	// pass on the claims this chain carries; none of them runs.
	chain[0].Raw[len(chain[0].Raw)-1] ^= 0x01

	_, err := e.Authorize(context.Background(), mcp.Call{Chain: chain, Tool: "search.query"})
	if stage := stageOf(t, err); stage != mcp.StageVerify {
		t.Errorf("refused at %q, want %q", stage, mcp.StageVerify)
	}
	if decider.asked != 0 {
		t.Errorf("the PDP was asked about an unverified chain")
	}
}

func TestAToolTheDeploymentCannotDescribeIsRefused(t *testing.T) {
	w := newWorld(t)
	decider := &pdp{allow: true}
	e := enforcer(t, w, decider, nil)

	// Within the grant — search.* covers it — and absent from the catalog.
	// An unknown tool has no tags, and no tags satisfies every tag-matching
	// constraint written to stop it, so the only safe answer is no.
	_, err := e.Authorize(context.Background(), mcp.Call{Chain: w.chain(nil), Tool: "search.unknown"})
	if stage := stageOf(t, err); stage != mcp.StageCatalog {
		t.Errorf("refused at %q, want %q", stage, mcp.StageCatalog)
	}
}

func TestAPolicyDenialRefusesTheCall(t *testing.T) {
	w := newWorld(t)
	e := enforcer(t, w, &pdp{allow: false}, nil)

	_, err := e.Authorize(context.Background(), mcp.Call{Chain: w.chain(nil), Tool: "search.query"})
	if stage := stageOf(t, err); stage != mcp.StagePolicy {
		t.Errorf("refused at %q, want %q", stage, mcp.StagePolicy)
	}
}

func TestAnUnreachablePDPRefusesTheCall(t *testing.T) {
	w := newWorld(t)
	e := enforcer(t, w, &pdp{allow: true, err: errors.New("connection refused")}, nil)

	_, err := e.Authorize(context.Background(), mcp.Call{Chain: w.chain(nil), Tool: "search.query"})
	if stage := stageOf(t, err); stage != mcp.StagePolicy {
		t.Errorf("refused at %q, want %q", stage, mcp.StagePolicy)
	}
}

func TestASequenceStoreThatCannotBeReadRefusesTheCall(t *testing.T) {
	w := newWorld(t)
	store := sequence.FailingStore{Err: errors.New("redis is down")}
	e := enforcer(t, w, &pdp{allow: true}, store)

	seq := &mda.Sequence{Constraints: []mda.Constraint{{
		ID:     "no-write-after-external-read",
		Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
		After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
	}}}

	_, err := e.Authorize(context.Background(), mcp.Call{Chain: w.chain(seq), Tool: "search.query"})
	if stage := stageOf(t, err); stage != mcp.StageSequence {
		t.Errorf("refused at %q, want %q", stage, mcp.StageSequence)
	}
}

// The pair no per-call check can see, through the enforcer rather than
// through pkg/sequence directly: both calls are within the grant and both are
// allowed by the PDP.
func TestAForbiddenSequenceIsRefusedThoughEachCallIsPermitted(t *testing.T) {
	w := newWorld(t)
	e := enforcer(t, w, &pdp{allow: true}, nil)

	seq := &mda.Sequence{Constraints: []mda.Constraint{{
		ID:     "no-write-after-external-read",
		Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
		After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
	}}}
	chain := w.chain(seq)
	ctx := context.Background()

	if _, err := e.Authorize(ctx, mcp.Call{Chain: chain, Tool: "search.write"}); err != nil {
		t.Fatalf("writing before any external read should be allowed: %v", err)
	}
	if _, err := e.Authorize(ctx, mcp.Call{Chain: chain, Tool: "search.fetch"}); err != nil {
		t.Fatalf("reading external content should be allowed: %v", err)
	}

	_, err := e.Authorize(ctx, mcp.Call{Chain: chain, Tool: "search.write"})
	if stage := stageOf(t, err); stage != mcp.StageSequence {
		t.Fatalf("refused at %q, want %q", stage, mcp.StageSequence)
	}
	denial, ok := sequence.Denied(err)
	if !ok {
		t.Fatalf("expected the refusal to wrap a *sequence.Denial, got %v", err)
	}
	if denial.Constraint != "no-write-after-external-read" {
		t.Errorf("denial names %q, want the constraint that fired", denial.Constraint)
	}
}

// A call the PDP refused never happened, so it must not be counted against
// the chain's invocation budget. Without this ordering, anything able to
// provoke a policy denial can spend a sponsor's budget to zero without ever
// invoking a tool.
func TestAPolicyDenialDoesNotSpendTheInvocationBudget(t *testing.T) {
	w := newWorld(t)
	decider := &pdp{allow: false}
	e := enforcer(t, w, decider, nil)

	chain := w.chain(&mda.Sequence{
		MaxInvocations: 1,
		Constraints: []mda.Constraint{{
			ID:     "no-write-after-external-read",
			Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
			After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
		}},
	})
	ctx := context.Background()

	if _, err := e.Authorize(ctx, mcp.Call{Chain: chain, Tool: "search.query"}); err == nil {
		t.Fatal("the PDP denied; the call should have been refused")
	}

	decider.allow = true
	if _, err := e.Authorize(ctx, mcp.Call{Chain: chain, Tool: "search.query"}); err != nil {
		t.Fatalf("the budget of one was spent on a call the PDP refused: %v", err)
	}
}

func TestNewRefusesAMissingCheck(t *testing.T) {
	w := newWorld(t)
	evaluator, err := sequence.NewEvaluator(sequence.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		call func() (*mcp.Enforcer, error)
	}{
		{"no verifier", func() (*mcp.Enforcer, error) {
			return mcp.New(nil, catalog, &pdp{}, evaluator)
		}},
		{"no catalog", func() (*mcp.Enforcer, error) {
			return mcp.New(w.verifier(), nil, &pdp{}, evaluator)
		}},
		{"no decider", func() (*mcp.Enforcer, error) {
			return mcp.New(w.verifier(), catalog, nil, evaluator)
		}},
		{"no sequence evaluator", func() (*mcp.Enforcer, error) {
			return mcp.New(w.verifier(), catalog, &pdp{}, nil)
		}},
		{"empty grant vocabulary", func() (*mcp.Enforcer, error) {
			return mcp.New(w.verifier(), catalog, &pdp{}, evaluator, mcp.WithGrantVocabulary("", "invoke"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); err == nil {
				t.Error("expected an error; an enforcer missing a check still authorizes calls")
			}
		})
	}
}

func TestAuthorizeRefusesACallNamingNoTool(t *testing.T) {
	w := newWorld(t)
	e := enforcer(t, w, &pdp{allow: true}, nil)

	_, err := e.Authorize(context.Background(), mcp.Call{Chain: w.chain(nil)})
	if stage := stageOf(t, err); stage != mcp.StageCatalog {
		t.Errorf("refused at %q, want %q", stage, mcp.StageCatalog)
	}
}

func TestToolsDescribesOnlyWhatItWasGiven(t *testing.T) {
	tools := mcp.Tools{"search.query": {"external-content"}}

	facts, err := tools.Describe("search.query", nil)
	if err != nil {
		t.Fatalf("a registered tool: %v", err)
	}
	if len(facts.Tags) != 1 || facts.Tags[0] != "external-content" {
		t.Errorf("tags = %v, want the registered tag", facts.Tags)
	}
	if _, err := tools.Describe("search.other", nil); err == nil {
		t.Error("an unregistered tool must be an error, not a tool with no tags")
	}
}

func TestCatalogFuncSuppliesConditionAttributes(t *testing.T) {
	w := newWorld(t)
	decider := &pdp{allow: true}

	evaluator, err := sequence.NewEvaluator(sequence.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	// The deployment names its own attributes; nothing derives them from
	// the arguments, so the condition below matches only because this
	// function says which argument it is written against.
	describe := mcp.CatalogFunc(func(_ string, args map[string]any) (mcp.Facts, error) {
		return mcp.Facts{Attributes: map[string]any{"args.index": args["index"]}}, nil
	})
	e, err := mcp.New(w.verifier(), describe, decider, evaluator)
	if err != nil {
		t.Fatal(err)
	}

	public := "public"
	conditioned := mda.Capability{
		Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.*"},
		Action:     mda.ActionPattern{Name: "invoke"},
		Conditions: map[string]mda.Condition{"args.index": {Equals: &public}},
	}
	root, err := issue.Sponsor(w.idp, w.spons, issue.Grant{
		Subject:      agentA,
		Audience:     audience,
		ID:           "jti-root",
		Lifetime:     time.Hour,
		IssuedAt:     w.now,
		MaxDepth:     issue.Depth(1),
		Capabilities: []mda.Capability{conditioned},
	})
	if err != nil {
		t.Fatal(err)
	}
	chain := mda.Chain{root}
	ctx := context.Background()

	if _, err := e.Authorize(ctx, mcp.Call{
		Chain: chain, Tool: "search.query", Arguments: map[string]any{"index": "public"},
	}); err != nil {
		t.Fatalf("the condition is met: %v", err)
	}

	_, err = e.Authorize(ctx, mcp.Call{
		Chain: chain, Tool: "search.query", Arguments: map[string]any{"index": "restricted"},
	})
	if stage := stageOf(t, err); stage != mcp.StagePermits {
		t.Errorf("refused at %q, want %q", stage, mcp.StagePermits)
	}
}
