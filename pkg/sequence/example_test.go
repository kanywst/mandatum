package sequence_test

import (
	"context"
	"fmt"

	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/sequence"
)

// The pattern per-call authorization cannot see: an agent reads untrusted
// external content, then writes to an internal system. Both calls are
// individually authorized. The pair is the exfiltration.
func Example() {
	// The sponsor's grant carries this rule, and it attenuates down the
	// chain like everything else — a sub-agent inherits it and cannot drop it.
	rule := &mda.Sequence{
		Constraints: []mda.Constraint{{
			ID:     "no-write-after-external-read",
			Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
			After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
		}},
	}

	e, err := sequence.NewEvaluator(sequence.NewMemoryStore())
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	chain := "01JB2X9K7P4Q8R3N6M0V5T2Y7C" // the sponsor's grant, at depth 0

	fetch := sequence.Action{Name: "invoke", ResourceType: "mcp_tool",
		ResourceTags: []string{"external-content"}}
	post := sequence.Action{Name: "invoke", ResourceType: "mcp_tool",
		ResourceTags: []string{"mutating"}}

	// Writing first is fine. Nothing has happened to forbid it.
	fmt.Println("write first:      ", verdict(e.Admit(ctx, chain, rule, post)))

	// Reading untrusted content is fine too.
	fmt.Println("read external:    ", verdict(e.Admit(ctx, chain, rule, fetch)))

	// The same write, after that read, is not — and the denial names the
	// rule, so an operator does not have to go and find it.
	fmt.Println("write after read: ", verdict(e.Admit(ctx, chain, rule, post)))

	// A sub-agent delegated after the fact is bound by the same history: the
	// state is keyed by the chain root, not by whoever is acting.
	fmt.Println("sub-agent writes: ", verdict(e.Admit(ctx, chain, rule, post)))

	// Output:
	// write first:       allowed
	// read external:     allowed
	// write after read:  denied by no-write-after-external-read
	// sub-agent writes:  denied by no-write-after-external-read
}

func verdict(err error) string {
	if err == nil {
		return "allowed"
	}
	if d, ok := sequence.Denied(err); ok {
		if d.Constraint == "" {
			return "denied: " + d.Reason
		}
		return "denied by " + d.Constraint
	}
	return "refused: " + err.Error()
}
