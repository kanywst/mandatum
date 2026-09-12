// Package sequence evaluates constraints over a chain's action history.
//
// This is the part per-call authorization structurally cannot do. An agent
// reads untrusted external content, then writes to an internal system. Both
// calls are legitimately authorized. The pair is an exfiltration, and no
// check that sees one call at a time can tell.
//
// A constraint says: once an action matching After has happened under this
// chain, any action matching Forbid is denied. That compiles to one bit per
// constraint plus a counter, so the state a chain accumulates is fixed-size
// no matter how long it runs — an unbounded history would be a denial of
// service on the enforcement point, and a history that is silently truncated
// would let a constraint expire.
//
// State is kept per chain root, not per agent. A constraint an agent inherits
// cannot be escaped by delegating to a fresh sub-agent, because the
// sub-agent's actions land in the same history.
//
// Everything here fails closed. If the state for a chain that declares
// constraints cannot be read, the action is denied. A sequence check that
// degrades to a per-call check is worse than none: the deployment believes it
// has a property it does not.
package sequence

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kanywst/mandatum/pkg/mda"
)

// Action is what an agent is attempting, in the terms constraints match on.
type Action struct {
	// Name is the action, matching mda.ActionMatcher.Action.
	Name string
	// ResourceType matches mda.ActionMatcher.ResourceType.
	ResourceType string
	// ResourceTags classify the resource: "external-content" for something
	// an agent should not trust, "mutating" for something that changes
	// state. Tags are how a deployment tells the sequence rules what its
	// tools actually do, and a constraint is only as good as they are.
	ResourceTags []string
}

// State is everything remembered about one chain root's history.
//
// It is deliberately small and does not grow. What a constraint needs to know
// is whether its trigger has fired, which is one bit; keeping the actions
// themselves would make the enforcement point's memory a function of how long
// an agent has been running.
type State struct {
	// Invocations counts actions admitted under this chain root.
	Invocations int
	// Triggered holds the IDs of constraints whose After has matched. Sorted,
	// so that a stored state has one representation.
	Triggered []string
}

// Store keeps sequence state. Implementations must make Update atomic with
// respect to concurrent callers for the same root: two agents acting at once
// under one chain must not each read the state before either writes, or a
// budget of one admits two actions.
type Store interface {
	// Update applies fn to the state for root and persists what it returns.
	// If fn returns an error, nothing is persisted and the error is returned
	// unchanged, so a caller can distinguish a denial from a storage fault.
	Update(ctx context.Context, root string, fn func(State) (State, error)) error
}

// Evaluator admits or denies actions against a chain's history.
type Evaluator struct {
	store Store
}

// NewEvaluator returns an Evaluator backed by store.
//
// A nil store is an error rather than a no-op evaluator. An evaluator that
// admits everything because nobody configured storage is the silent
// degradation this package exists to prevent.
func NewEvaluator(store Store) (*Evaluator, error) {
	if store == nil {
		return nil, errors.New("sequence: a Store is required; an evaluator with nowhere to keep history admits everything")
	}
	return &Evaluator{store: store}, nil
}

// Denial reports an action refused by a sequence constraint.
type Denial struct {
	// Constraint is the ID of the rule that fired, or empty when the
	// invocation budget was exhausted. A denial that cannot name its rule
	// leaves an operator guessing.
	Constraint string
	// Reason is a sentence an operator can act on.
	Reason string
}

func (d *Denial) Error() string {
	if d.Constraint == "" {
		return "sequence: " + d.Reason
	}
	return fmt.Sprintf("sequence: %s (constraint %q)", d.Reason, d.Constraint)
}

// Denied reports whether err is a constraint denial rather than a fault.
//
// Both deny the action. The difference matters for what an operator does
// next: a denial is the system working, a fault is the system broken.
func Denied(err error) (*Denial, bool) {
	var d *Denial
	ok := errors.As(err, &d)
	return d, ok
}

// Admit records an action against a chain root's history, or refuses it.
//
// A nil error means the action is permitted and has been counted. Any error
// means it is refused: either a *Denial from a constraint, or a storage fault
// that leaves the history unknown. Both refuse, because an action admitted
// against a history nobody could read is an action nobody constrained.
//
// seq is the acting assertion's constraints. Because constraints may only
// tighten down a chain (specification §6, rule 5), the leaf's set includes
// everything its ancestors imposed.
func (e *Evaluator) Admit(ctx context.Context, root string, seq *mda.Sequence, action Action) error {
	if seq == nil {
		// Nothing to constrain, so nothing to record. Storing history for a
		// chain with no constraints would cost writes for no property.
		return nil
	}
	if root == "" {
		return errors.New("sequence: a chain root is required; without it a history cannot be kept per chain")
	}
	if err := Validate(seq); err != nil {
		return err
	}

	return e.store.Update(ctx, root, func(s State) (State, error) {
		return admit(s, seq, action)
	})
}

// admit is the pure decision, separated from storage so that it can be
// tested and reasoned about without a store in the way.
func admit(s State, seq *mda.Sequence, action Action) (State, error) {
	// The budget is checked before the constraints, so an exhausted chain
	// gets one clear reason rather than whichever rule happens to fire.
	if seq.MaxInvocations > 0 && s.Invocations >= seq.MaxInvocations {
		return s, &Denial{Reason: fmt.Sprintf(
			"the chain's %d permitted invocations are used up", seq.MaxInvocations)}
	}

	for _, c := range seq.Constraints {
		if !slices.Contains(s.Triggered, c.ID) {
			continue
		}
		if matches(c.Forbid, action) {
			return s, &Denial{
				Constraint: c.ID,
				Reason: fmt.Sprintf(
					"%q on %q is forbidden once %s has happened under this chain",
					action.Name, action.ResourceType, describe(c.After)),
			}
		}
	}

	// Admitted. Fire any triggers this action matches, so the next action
	// sees them. A constraint whose Forbid and After both match this action
	// still admits it — the trigger fires after the check, which is what
	// "once X has happened" means.
	next := State{Invocations: s.Invocations + 1, Triggered: slices.Clone(s.Triggered)}
	for _, c := range seq.Constraints {
		if !slices.Contains(next.Triggered, c.ID) && matches(c.After, action) {
			next.Triggered = append(next.Triggered, c.ID)
		}
	}
	slices.Sort(next.Triggered)
	return next, nil
}

// matches reports whether an action satisfies a matcher.
//
// An empty field matches anything, so an empty matcher matches every action.
// That is meaningful for Forbid — "after reading untrusted content, do
// nothing else" — and a trap for After, which is why Validate refuses it.
func matches(m mda.ActionMatcher, a Action) bool {
	if m.Action != "" && m.Action != a.Name {
		return false
	}
	if m.ResourceType != "" && m.ResourceType != a.ResourceType {
		return false
	}
	for _, tag := range m.ResourceTags {
		if !slices.Contains(a.ResourceTags, tag) {
			return false
		}
	}
	return true
}

func isEmpty(m mda.ActionMatcher) bool {
	return m.Action == "" && m.ResourceType == "" && len(m.ResourceTags) == 0
}

func describe(m mda.ActionMatcher) string {
	switch {
	case len(m.ResourceTags) > 0:
		return fmt.Sprintf("an action on %v", m.ResourceTags)
	case m.ResourceType != "":
		return "an action on " + m.ResourceType
	case m.Action != "":
		return m.Action
	default:
		return "any action"
	}
}

// Validate reports whether a sequence compiles to a bounded automaton.
//
// It is called on every Admit rather than trusted from issuance, because an
// assertion reaching a verifier may have been issued by something that did
// not check. Constraints that cannot compile are refused rather than
// approximated: a constraint evaluated loosely is one an operator believes in
// and does not have.
func Validate(seq *mda.Sequence) error {
	if seq == nil {
		return nil
	}
	if seq.MaxInvocations < 0 {
		return fmt.Errorf("sequence: max_invocations %d is negative", seq.MaxInvocations)
	}
	if seq.MaxInvocations == 0 && len(seq.Constraints) == 0 {
		return errors.New("sequence: constrains nothing")
	}

	seen := make(map[string]struct{}, len(seq.Constraints))
	for i, c := range seq.Constraints {
		if c.ID == "" {
			return fmt.Errorf("sequence: constraints[%d] has no id; a denial must be able to name the rule that fired", i)
		}
		if _, dup := seen[c.ID]; dup {
			// Two rules under one name make the state bit ambiguous: which
			// of them fired, and which does a denial refer to?
			return fmt.Errorf("sequence: constraint id %q appears more than once", c.ID)
		}
		seen[c.ID] = struct{}{}

		// An empty After is a trap. A constraint says "once X has happened",
		// so an empty trigger needs some action to have happened first and
		// becomes active from the second action onward — not the first,
		// which is what whoever wrote it meant. An unconditional prohibition
		// belongs in the capability set, where it applies from the start and
		// attenuates down the chain like everything else.
		if isEmpty(c.After) {
			return fmt.Errorf(
				"sequence: constraint %q has an empty trigger; a sequence rule fires after something, "+
					"so this would take effect from the second action, not the first. "+
					"To forbid an action outright, leave it out of the capability set", c.ID)
		}
	}
	return nil
}
