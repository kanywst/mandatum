package sequence

import (
	"context"
	"errors"
	"fmt"
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
// Entries are not evicted on a timer. Dropping a live chain's history resets
// the constraints it is under, which widens authority, so expiry is the
// caller's decision through Forget — usually when the chain's root assertion
// expires or is revoked. What the store does instead is refuse to grow past
// MaxRoots, because a process that runs out of memory stops enforcing
// entirely.
//
// The zero value is ready to use and applies DefaultMaxRoots.
type MemoryStore struct {
	// MaxRoots caps how many chain roots are tracked. Zero applies
	// DefaultMaxRoots; a negative value removes the cap, which is a choice
	// to make deliberately and not a default.
	MaxRoots int

	mu     sync.Mutex
	states map[string]State
}

// DefaultMaxRoots bounds a store whose MaxRoots is unset. It is generous
// enough not to be hit by a normal deployment and small enough that an
// enforcement point cannot be exhausted by minting chains.
const DefaultMaxRoots = 100_000

// NewMemoryStore returns an empty store with the default cap.
func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

// Len reports how many chain roots are tracked.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.states)
}

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

	// Refuse rather than evict. Evicting a live chain would clear the
	// triggers it is under, so the cheapest way past a constraint would be
	// to fill the store.
	if _, known := m.states[root]; !known {
		if limit := m.maxRoots(); limit > 0 && len(m.states) >= limit {
			return fmt.Errorf(
				"sequence: the history store is holding %d chain roots, its limit; "+
					"call Forget for chains that have expired, or raise MaxRoots", limit)
		}
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

func (m *MemoryStore) maxRoots() int {
	if m.MaxRoots == 0 {
		return DefaultMaxRoots
	}
	return m.MaxRoots
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
