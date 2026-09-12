package sequence

import (
	"context"
	"errors"
	"slices"
	"sync"
)

// MemoryStore keeps sequence state in this process.
//
// Suitable for a single enforcement point, for tests, and for development.
// It is not suitable for a deployment with more than one PEP: state is kept
// per chain root precisely so that a constraint cannot be escaped, and two
// PEPs with separate memories give an agent two histories to spend. Use a
// replicated store there.
//
// The zero value is ready to use.
type MemoryStore struct {
	mu     sync.Mutex
	states map[string]State
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

// Update applies fn to the state for root under a lock, so two agents acting
// at once under one chain cannot both read the state before either writes.
// Without that, a budget of one admits two actions.
func (m *MemoryStore) Update(ctx context.Context, root string, fn func(State) (State, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.states == nil {
		m.states = map[string]State{}
	}

	next, err := fn(m.states[root])
	if err != nil {
		// Nothing is persisted on a denial. A refused action did not happen,
		// so it must not count against the budget or fire a trigger.
		return err
	}
	m.states[root] = next
	return nil
}

// Get returns the state for a chain root, for inspection and tests.
func (m *MemoryStore) Get(root string) State {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[root]
	return State{Invocations: s.Invocations, Triggered: slices.Clone(s.Triggered)}
}

// Forget discards the history for a chain root.
//
// Intended for a chain that has expired or been revoked, where the state is
// dead weight. Calling it on a live chain resets the constraints that chain
// is under, which is why it is a named operation rather than an eviction
// policy: dropping history is a decision, not a housekeeping detail.
func (m *MemoryStore) Forget(root string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.states, root)
}

// FailingStore is a Store that always reports a fault.
//
// Exported because "what happens when the history cannot be read" is a
// property worth asserting in the tests of anything built on this package,
// and every such test needs this.
type FailingStore struct{ Err error }

// Update always fails.
func (f FailingStore) Update(context.Context, string, func(State) (State, error)) error {
	if f.Err != nil {
		return f.Err
	}
	return errors.New("sequence: the history store is unavailable")
}
