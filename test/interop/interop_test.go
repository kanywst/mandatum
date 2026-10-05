//go:build interop

// Package interop runs one fixed scenario through the enforcement point
// against every Policy Decision Point it is given.
//
// The v0.2 gate is "works against three PDPs from different vendors with no
// implementation-specific code paths". The second half is what this file is
// built around: there is one scenario, one client and one set of
// expectations, and nothing here knows which PDP it is talking to. What
// differs between PDPs is their policy, which lives beside this file in each
// PDP's own format and says the same thing in each: see README.md.
//
// The PDPs are named in MANDATUM_INTEROP_PDPS as comma-separated
// name=endpoint entries, the endpoint being the full Access Evaluation URL,
// each optionally followed by flags after semicolons:
//
//	MANDATUM_INTEROP_PDPS='opa=http://127.0.0.1:13000/access/v1/evaluation,cerbos=http://127.0.0.1:3592/access/v1/evaluation;no-request-id;no-context' \
//	  go test -tags interop ./test/interop/
//
// The flags are the only per-PDP knobs, and both describe the PDP rather
// than change what is sent to it:
//
//   - no-request-id: the PDP does not echo X-Request-ID as the
//     specification requires, so the client is configured not to send one,
//     with the option every deployment has (authzen.WithRequestID). The
//     client refuses a missing or different echo, which is right, and with
//     these PDPs it would refuse every answer.
//   - no-context: the PDP's policy language cannot read the evaluation
//     request's context, so no policy written for it can condition on
//     context.agent. The case that needs one is skipped and logged, not
//     passed.
//
// With none named, the test fails rather than skips: a green interop run
// that talked to nothing is the result this exists to rule out.
package interop

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"os"
	"strings"
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

// The scenario's fixed values. Every policy beside this file is written
// against exactly these, so changing one here means changing all of them.
const (
	idp      = "https://idp.example.org"
	audience = "https://mcp.example.org"
	sponsor  = "u-8f31c02e"
	stranger = "u-0d4be771"
	agent    = "spiffe://example.org/ns/agents/retriever"
	impostor = "spiffe://example.org/ns/agents/unvetted"
)

// indexMapping is a declared mapping, so that the scenario covers what the
// PDP sees when a tool declares one as well as the default mapping.
const indexMapping = `{"evaluation": {
	"subject": { "type": "identity", "id": "$token.sub" },
	"action": { "name": "query" },
	"resource": { "type": "index", "id": "$params.arguments.index" },
	"context": { "agent": "$token.?client_id" }
}}`

type world struct {
	t    *testing.T
	ring *jose.KeyRing
	idp  issue.Signer
	now  time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ring := jose.NewKeyRing()
	if err := ring.Add(idp, "idp-1", pub); err != nil {
		t.Fatal(err)
	}
	return &world{
		t:    t,
		ring: ring,
		idp:  issue.Signer{ID: idp, KeyID: "idp-1", Key: priv},
		now:  time.Now().Truncate(time.Second),
	}
}

// chain is a sponsor's grant to one agent over every search tool, so that
// the chain's own grant never decides a case here: every refusal below has
// to come from the PDP.
func (w *world) chain(subject, to string) mda.Chain {
	w.t.Helper()
	root, err := issue.Sponsor(w.idp, mda.Sponsor{Issuer: idp, Subject: subject}, issue.Grant{
		Subject:  to,
		Audience: audience,
		ID:       "jti-" + subject + "-" + to,
		Lifetime: time.Hour,
		IssuedAt: w.now,
		MaxDepth: issue.Depth(1),
		Capabilities: []mda.Capability{{
			Resource: mda.ResourcePattern{Type: mcp.DefaultResourceType, ID: "search.*"},
			Action:   mda.ActionPattern{Name: mcp.DefaultAction},
		}},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return mda.Chain{root}
}

type noRevocations struct{}

func (noRevocations) IsRevoked(context.Context, string) (bool, error) { return false, nil }

type pdp struct {
	name, endpoint string
	noRequestID    bool
	noContext      bool
}

func pdps(t *testing.T) []pdp {
	t.Helper()
	raw := os.Getenv("MANDATUM_INTEROP_PDPS")
	if raw == "" {
		t.Fatal("MANDATUM_INTEROP_PDPS names no PDP; an interop run against nothing proves nothing")
	}
	var out []pdp
	for _, entry := range strings.Split(raw, ",") {
		fields := strings.Split(strings.TrimSpace(entry), ";")
		name, endpoint, ok := strings.Cut(fields[0], "=")
		if !ok || name == "" || endpoint == "" {
			t.Fatalf("MANDATUM_INTEROP_PDPS entry %q is not name=endpoint", entry)
		}
		p := pdp{name: name, endpoint: endpoint}
		for _, flag := range fields[1:] {
			switch flag {
			case "no-request-id":
				p.noRequestID = true
			case "no-context":
				p.noContext = true
			default:
				t.Fatalf("MANDATUM_INTEROP_PDPS entry %q has unknown flag %q", entry, flag)
			}
		}
		out = append(out, p)
	}
	return out
}

func TestEveryPDPReachesTheSameDecisions(t *testing.T) {
	for _, p := range pdps(t) {
		t.Run(p.name, func(t *testing.T) {
			w := newWorld(t)

			opts := []authzen.Option{authzen.WithHTTPClient(&http.Client{Timeout: 10 * time.Second})}
			if p.noRequestID {
				opts = append(opts, authzen.WithRequestID(func() string { return "" }))
			}
			client, err := authzen.New(p.endpoint, opts...)
			if err != nil {
				t.Fatal(err)
			}
			mapping, err := authzen.ParseMapping([]byte(indexMapping))
			if err != nil {
				t.Fatal(err)
			}
			catalog := mcp.CatalogFunc(func(tool string, _ map[string]any) (mcp.Facts, error) {
				facts := mcp.Facts{}
				if tool == "search.index" {
					facts.Mapping = mapping
				}
				return facts, nil
			})
			verifier, err := verify.New(w.ring, noRevocations{}, audience)
			if err != nil {
				t.Fatal(err)
			}
			sequences, err := sequence.NewEvaluator(sequence.NewMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			enforcer, err := mcp.New(verifier, catalog, client, sequences, mcp.WithServer(audience))
			if err != nil {
				t.Fatal(err)
			}

			// Each case differs from the allowed one in exactly one field
			// the PDP has to read, so a PDP that ignores that field allows
			// it and fails here.
			cases := []struct {
				name         string
				call         mcp.Call
				allow        bool
				readsContext bool
			}{
				{"the policy's own case", mcp.Call{Chain: w.chain(sponsor, agent), Tool: "search.query"}, true, false},
				{"another tool (resource.id)", mcp.Call{Chain: w.chain(sponsor, agent), Tool: "search.fetch"}, false, false},
				{"another sponsor (subject.id)", mcp.Call{Chain: w.chain(stranger, agent), Tool: "search.query"}, false, false},
				{"another agent (context.agent)", mcp.Call{Chain: w.chain(sponsor, impostor), Tool: "search.query"}, false, true},
				{"declared mapping, permitted index", mcp.Call{Chain: w.chain(sponsor, agent), Tool: "search.index",
					Arguments: map[string]any{"index": "public"}}, true, false},
				{"declared mapping, another index (resource.id)", mcp.Call{Chain: w.chain(sponsor, agent), Tool: "search.index",
					Arguments: map[string]any{"index": "private"}}, false, false},
			}
			for _, c := range cases {
				if c.readsContext && p.noContext {
					t.Logf("%s: skipped, this PDP's policy cannot read the request context", c.name)
					continue
				}
				_, err := enforcer.Authorize(context.Background(), c.call)
				switch {
				case c.allow && err != nil:
					t.Errorf("%s: want allowed, got %v", c.name, err)
				case !c.allow && err == nil:
					t.Errorf("%s: want refused by the PDP, got allowed", c.name)
				case !c.allow:
					// Refused is not enough: refused because the PDP could
					// not be reached or answered something this client
					// cannot read would pass a deny case while proving
					// nothing about interoperability.
					refusal, ok := mcp.Refused(err)
					if !ok || refusal.Stage != mcp.StagePolicy || !strings.Contains(err.Error(), "denied") {
						t.Errorf("%s: want a policy denial, got %v", c.name, err)
					}
				}
			}
		})
	}
}
