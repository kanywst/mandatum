package sequence_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/sequence"
)

const root = "jti-root"

// The pattern the whole package exists for: reading untrusted content and
// then mutating something. Each action is individually fine.
func exfiltration() *mda.Sequence {
	return &mda.Sequence{
		Constraints: []mda.Constraint{{
			ID:     "no-write-after-external-read",
			Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
			After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
		}},
	}
}

func read() sequence.Action {
	return sequence.Action{Name: "invoke", ResourceType: "mcp_tool", ResourceTags: []string{"external-content"}}
}

func write() sequence.Action {
	return sequence.Action{Name: "invoke", ResourceType: "mcp_tool", ResourceTags: []string{"mutating"}}
}

func harmless() sequence.Action {
	return sequence.Action{Name: "invoke", ResourceType: "mcp_tool", ResourceTags: []string{"internal"}}
}

func evaluator(t *testing.T, store sequence.Store) *sequence.Evaluator {
	t.Helper()
	e, err := sequence.NewEvaluator(store)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestTheSequenceNoPerCallCheckCanSee(t *testing.T) {
	ctx := context.Background()
	e := evaluator(t, sequence.NewMemoryStore())
	seq := exfiltration()

	// A write on its own is fine. Nothing has triggered the rule.
	if err := e.Admit(ctx, root, seq, write()); err != nil {
		t.Fatalf("a write before any external read was denied: %v", err)
	}

	// Reading untrusted content is also fine.
	if err := e.Admit(ctx, root, seq, read()); err != nil {
		t.Fatalf("reading external content was denied: %v", err)
	}

	// The pair is not. This is the whole point.
	err := e.Admit(ctx, root, seq, write())
	if err == nil {
		t.Fatal("a write after an external read was admitted")
	}
	d, ok := sequence.Denied(err)
	if !ok {
		t.Fatalf("expected a constraint denial, got %v", err)
	}
	if d.Constraint != "no-write-after-external-read" {
		t.Errorf("denial names %q; an operator cannot tell which rule fired", d.Constraint)
	}
}

// A constraint an agent inherits must not be escapable by delegating onward.
// State is keyed by chain root for exactly this reason: a sub-agent's actions
// land in the same history as its delegator's.
func TestASubAgentCannotEscapeAnInheritedConstraint(t *testing.T) {
	ctx := context.Background()
	e := evaluator(t, sequence.NewMemoryStore())
	seq := exfiltration()

	// The parent reads untrusted content.
	if err := e.Admit(ctx, root, seq, read()); err != nil {
		t.Fatal(err)
	}
	// A freshly delegated sub-agent, acting under the same chain root, is
	// still bound by what its delegator did.
	if err := e.Admit(ctx, root, seq, write()); err == nil {
		t.Fatal("a sub-agent wrote after its delegator read external content")
	}

	// A different chain, from a different sponsor grant, is unaffected.
	if err := e.Admit(ctx, "jti-other-root", seq, write()); err != nil {
		t.Errorf("an unrelated chain was caught by this chain's history: %v", err)
	}
}

func TestInvocationBudget(t *testing.T) {
	ctx := context.Background()
	store := sequence.NewMemoryStore()
	e := evaluator(t, store)
	seq := &mda.Sequence{MaxInvocations: 2}

	for i := range 2 {
		if err := e.Admit(ctx, root, seq, harmless()); err != nil {
			t.Fatalf("invocation %d of 2 was denied: %v", i+1, err)
		}
	}

	err := e.Admit(ctx, root, seq, harmless())
	if err == nil {
		t.Fatal("the budget did not stop the third invocation")
	}
	d, ok := sequence.Denied(err)
	if !ok {
		t.Fatalf("expected a denial, got %v", err)
	}
	if d.Constraint != "" {
		t.Errorf("a budget denial named constraint %q", d.Constraint)
	}
	if !strings.Contains(d.Reason, "used up") {
		t.Errorf("unhelpful reason: %s", d.Reason)
	}

	if got := store.Get(root).Invocations; got != 2 {
		t.Errorf("a refused action counted against the budget: %d invocations recorded", got)
	}
}

// The state a chain accumulates must not grow with its history, or a
// long-running agent becomes a memory leak at the enforcement point.
func TestStateStaysBounded(t *testing.T) {
	ctx := context.Background()
	store := sequence.NewMemoryStore()
	e := evaluator(t, store)
	seq := exfiltration()

	for range 1000 {
		if err := e.Admit(ctx, root, seq, harmless()); err != nil {
			t.Fatal(err)
		}
	}

	s := store.Get(root)
	if s.Invocations != 1000 {
		t.Errorf("invocations = %d", s.Invocations)
	}
	if len(s.Triggered) > len(seq.Constraints) {
		t.Errorf("triggered set has %d entries for %d constraints; state is growing with history",
			len(s.Triggered), len(seq.Constraints))
	}
}

// If the history cannot be read, the action is refused. A sequence check that
// degrades to a per-call check is worse than none, because the deployment
// believes it has a property it does not.
func TestAnUnreadableHistoryDenies(t *testing.T) {
	e := evaluator(t, sequence.FailingStore{Err: errors.New("replica unreachable")})

	err := e.Admit(context.Background(), root, exfiltration(), harmless())
	if err == nil {
		t.Fatal("admitted an action against a history that could not be read")
	}
	if _, isDenial := sequence.Denied(err); isDenial {
		t.Error("a storage fault was reported as a constraint denial; an operator would look in the wrong place")
	}
	if !strings.Contains(err.Error(), "replica unreachable") {
		t.Errorf("the underlying fault was swallowed: %v", err)
	}
}

func TestNoConstraintsMeansNoBookkeeping(t *testing.T) {
	store := sequence.NewMemoryStore()
	e := evaluator(t, store)

	if err := e.Admit(context.Background(), root, nil, harmless()); err != nil {
		t.Fatalf("an unconstrained chain was denied: %v", err)
	}
	if got := store.Get(root).Invocations; got != 0 {
		t.Errorf("recorded %d invocations for a chain with no constraints", got)
	}
}

// An evaluator with nowhere to keep history would admit everything. That is
// the silent degradation this package exists to prevent, so it cannot be
// constructed.
func TestAnEvaluatorWithoutAStoreCannotExist(t *testing.T) {
	if _, err := sequence.NewEvaluator(nil); err == nil {
		t.Fatal("built an evaluator with no store")
	}
}

func TestAdmitRequiresAChainRoot(t *testing.T) {
	e := evaluator(t, sequence.NewMemoryStore())
	if err := e.Admit(context.Background(), "", exfiltration(), harmless()); err == nil {
		t.Fatal("admitted an action with no chain root; the history would be shared by everything")
	}
}

// The trigger fires after the check, which is what "once X has happened"
// means: an action that is both the trigger and the forbidden thing is
// admitted once, and the next one is not.
func TestATriggerFiresAfterTheActionThatSetIt(t *testing.T) {
	ctx := context.Background()
	e := evaluator(t, sequence.NewMemoryStore())
	seq := &mda.Sequence{Constraints: []mda.Constraint{{
		ID:     "once-only",
		Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
		After:  mda.ActionMatcher{ResourceTags: []string{"mutating"}},
	}}}

	if err := e.Admit(ctx, root, seq, write()); err != nil {
		t.Fatalf("the first write was denied: %v", err)
	}
	if err := e.Admit(ctx, root, seq, write()); err == nil {
		t.Fatal("the second write was admitted")
	}
}

// An empty trigger is a trap: "once X has happened" needs something to have
// happened, so the rule would take effect from the second action rather than
// the first, which is not what anyone writing it means. Refused, with the
// message pointing at where an unconditional prohibition belongs.
func TestAnEmptyTriggerIsRefused(t *testing.T) {
	e := evaluator(t, sequence.NewMemoryStore())
	seq := &mda.Sequence{Constraints: []mda.Constraint{{
		ID:     "nothing-mutating-ever",
		Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
		After:  mda.ActionMatcher{},
	}}}

	err := e.Admit(context.Background(), root, seq, write())
	if err == nil {
		t.Fatal("accepted a constraint with an empty trigger")
	}
	if !strings.Contains(err.Error(), "capability set") {
		t.Errorf("the message does not say where this belongs instead: %v", err)
	}
}

// An empty Forbid is meaningful and stays allowed: "after reading untrusted
// content, do nothing else at all".
func TestAnEmptyForbidStopsEverythingAfterTheTrigger(t *testing.T) {
	ctx := context.Background()
	e := evaluator(t, sequence.NewMemoryStore())
	seq := &mda.Sequence{Constraints: []mda.Constraint{{
		ID:     "quarantine-after-external-read",
		Forbid: mda.ActionMatcher{},
		After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
	}}}

	if err := e.Admit(ctx, root, seq, harmless()); err != nil {
		t.Fatalf("denied before the trigger: %v", err)
	}
	if err := e.Admit(ctx, root, seq, read()); err != nil {
		t.Fatalf("denied the trigger itself: %v", err)
	}
	if err := e.Admit(ctx, root, seq, harmless()); err == nil {
		t.Fatal("admitted an action after the quarantine trigger")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		seq  *mda.Sequence
		want string
	}{
		{"nil is fine", nil, ""},
		{"a budget alone", &mda.Sequence{MaxInvocations: 1}, ""},
		{"a constraint alone", exfiltration(), ""},
		{"constrains nothing", &mda.Sequence{}, "constrains nothing"},
		{"negative budget", &mda.Sequence{MaxInvocations: -1}, "is negative"},
		{
			"a constraint with no id",
			&mda.Sequence{Constraints: []mda.Constraint{{Forbid: mda.ActionMatcher{Action: "x"}}}},
			"has no id",
		},
		{
			"two constraints under one id",
			&mda.Sequence{Constraints: []mda.Constraint{
				{ID: "a", After: mda.ActionMatcher{Action: "read"}},
				{ID: "a", After: mda.ActionMatcher{Action: "write"}},
			}},
			"more than once",
		},
		{
			"an empty trigger",
			&mda.Sequence{Constraints: []mda.Constraint{{
				ID:     "a",
				Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
			}}},
			"empty trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sequence.Validate(tt.seq)
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("rejected a valid sequence: %v", err)
			case tt.want != "" && err == nil:
				t.Fatal("accepted an invalid sequence")
			case tt.want != "" && !strings.Contains(err.Error(), tt.want):
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// Two agents acting at once under one chain must not each read the state
// before either writes, or a budget of one admits two actions.
func TestConcurrentAdmissionsShareOneBudget(t *testing.T) {
	ctx := context.Background()
	store := sequence.NewMemoryStore()
	e := evaluator(t, store)

	const budget = 50
	const attempts = 200
	seq := &mda.Sequence{MaxInvocations: budget}

	var wg sync.WaitGroup
	admitted := make(chan struct{}, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.Admit(ctx, root, seq, harmless()); err == nil {
				admitted <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(admitted)

	if got := len(admitted); got != budget {
		t.Errorf("%d actions admitted against a budget of %d", got, budget)
	}
	if got := store.Get(root).Invocations; got != budget {
		t.Errorf("recorded %d invocations, want %d", got, budget)
	}
}

func TestForgetDiscardsAChainsHistory(t *testing.T) {
	ctx := context.Background()
	store := sequence.NewMemoryStore()
	e := evaluator(t, store)
	seq := exfiltration()

	if err := e.Admit(ctx, root, seq, read()); err != nil {
		t.Fatal(err)
	}
	if err := e.Admit(ctx, root, seq, write()); err == nil {
		t.Fatal("expected the constraint to fire")
	}

	store.Forget(root)

	if err := e.Admit(ctx, root, seq, write()); err != nil {
		t.Errorf("history survived Forget: %v", err)
	}
}
