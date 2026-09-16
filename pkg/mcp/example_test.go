package mcp_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/kanywst/mandatum/pkg/authzen"
	"github.com/kanywst/mandatum/pkg/issue"
	"github.com/kanywst/mandatum/pkg/jose"
	"github.com/kanywst/mandatum/pkg/mcp"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/sequence"
	"github.com/kanywst/mandatum/pkg/verify"
)

// alwaysAllows is the PDP after somebody has taken it over. It is not a
// straw man: a PDP is a network service, and a policy that says yes is one
// misconfiguration away in a healthy one.
type alwaysAllows struct{}

func (alwaysAllows) Evaluate(context.Context, authzen.Request) (authzen.Decision, error) {
	return authzen.Decision{Allowed: true}, nil
}

// The ordering specification §8 requires, and what it buys. A human sponsors
// an agent to search; the agent asks to wipe the database, and a Policy
// Decision Point that permits everything says yes. The call is still
// refused, because the chain is compared against the request before the PDP
// is asked — and it is refused without the PDP being asked at all.
func Example() {
	const (
		idp      = "https://idp.example.org"
		audience = "https://mcp.example.org"
		agent    = "spiffe://example.org/ns/agents/retriever"
	)

	// A sponsor grant over search.*, nothing else.
	ring := jose.NewKeyRing()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	if err := ring.Add(idp, "idp-2026", pub); err != nil {
		panic(err)
	}
	now := time.Unix(1789200000, 0)
	root, err := issue.Sponsor(
		issue.Signer{ID: idp, KeyID: "idp-2026", Key: priv},
		mda.Sponsor{Issuer: idp, Subject: "u-8f31c02e", AuthenticationMethods: []string{"pwd", "hwk"}},
		issue.Grant{
			Subject:  agent,
			Audience: audience,
			ID:       "jti-root",
			Lifetime: time.Hour,
			IssuedAt: now,
			MaxDepth: issue.Depth(1),
			Capabilities: []mda.Capability{{
				Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.*"},
				Action:   mda.ActionPattern{Name: "invoke"},
			}},
		})
	if err != nil {
		panic(err)
	}

	// The enforcement point: a verifier, what the deployment knows about its
	// own tools, a PDP, and somewhere to keep each chain's history.
	verifier, err := verify.New(ring, noRevocations{}, audience,
		verify.WithClock(func() time.Time { return now.Add(time.Minute) }))
	if err != nil {
		panic(err)
	}
	sequences, err := sequence.NewEvaluator(sequence.NewMemoryStore())
	if err != nil {
		panic(err)
	}
	enforcer, err := mcp.New(
		verifier,
		mcp.Tools{"search.query": nil, "admin.wipeAll": nil},
		alwaysAllows{},
		sequences,
		mcp.WithServer(audience),
	)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	chain := mda.Chain{root}

	fmt.Println("search.query: ", outcome(enforcer.Authorize(ctx, mcp.Call{Chain: chain, Tool: "search.query"})))
	fmt.Println("admin.wipeAll:", outcome(enforcer.Authorize(ctx, mcp.Call{Chain: chain, Tool: "admin.wipeAll"})))

	// Output:
	// search.query:  allowed
	// admin.wipeAll: refused at permits
}

func outcome(_ *mcp.Authorized, err error) string {
	if err == nil {
		return "allowed"
	}
	if refusal, ok := mcp.Refused(err); ok {
		return "refused at " + string(refusal.Stage)
	}
	return "refused: " + err.Error()
}
