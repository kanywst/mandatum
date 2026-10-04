package authzen_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/kanywst/mandatum/pkg/authzen"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/verify"
)

func verified() *verify.Result {
	return &verify.Result{
		Sponsor: mda.Sponsor{
			Issuer:                "https://idp.example.org",
			Subject:               "u-8f31c02e",
			AuthenticationMethods: []string{"pwd", "hwk"},
			AuthenticatedAt:       1789199400,
		},
		Agent:       "spiffe://example.org/ns/agents/retriever",
		Actors:      []string{"spiffe://example.org/ns/agents/planner", "spiffe://example.org/ns/agents/retriever"},
		Depth:       1,
		ChainDigest: "sha-256:abc",
		LeafID:      "jti-child",
	}
}

func mustParse(t *testing.T, raw string) *authzen.Mapping {
	t.Helper()
	m, err := authzen.ParseMapping([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMapping: %v", err)
	}
	return m
}

func resolve(t *testing.T, m *authzen.Mapping, args map[string]any) ([]authzen.Request, error) {
	t.Helper()
	return m.ToolCallRequests(context.Background(), verified(), authzen.ToolCall{Name: "tool", Arguments: args})
}

func isMappingError(t *testing.T, err error) {
	t.Helper()
	var me *authzen.MappingError
	if !errors.As(err, &me) {
		t.Fatalf("expected a *MappingError, got %T: %v", err, err)
	}
}

// The binding's single-evaluation example, get_customer, with the chain in
// place of the access token. Every value it resolves is asserted, and so are
// the three the enforcement point supplies.
func TestTheBindingsSingleEvaluationExample(t *testing.T) {
	m := mustParse(t, `{
		"evaluation": {
			"subject": { "type": "identity", "id": "$token.sub" },
			"action": { "name": "get_customer" },
			"resource": { "type": "customer", "id": "$params.arguments.id" },
			"context": { "agent": "$token.?client_id", "case": "$params.arguments.case" }
		}
	}`)

	got, err := resolve(t, m, map[string]any{"id": "cust-12345", "case": "case-67890"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d requests, want 1", len(got))
	}
	r := got[0]
	if r.Subject.Type != "identity" || r.Subject.ID != "u-8f31c02e" {
		t.Errorf("subject = %+v, want the sponsor", r.Subject)
	}
	if r.Subject.Properties["iss"] != "https://idp.example.org" {
		t.Error("the sponsor's issuer is missing from subject.properties")
	}
	if r.Action.Name != "get_customer" {
		t.Errorf("action.name = %q", r.Action.Name)
	}
	if r.Resource.Type != "customer" || r.Resource.ID != "cust-12345" {
		t.Errorf("resource = %+v", r.Resource)
	}
	if r.Context["agent"] != verified().Agent {
		t.Errorf("context.agent = %v, want the acting agent", r.Context["agent"])
	}
	if r.Context["case"] != "case-67890" {
		t.Errorf("context.case = %v", r.Context["case"])
	}
	d, ok := r.Context[authzen.DelegationContextKey].(authzen.Delegation)
	if !ok || d.Chain != "sha-256:abc" || d.Leaf != "jti-child" {
		t.Errorf("context[%q] = %#v, want the verified chain", authzen.DelegationContextKey, r.Context[authzen.DelegationContextKey])
	}
}

// The binding's multi-evaluation example. The top-level members are defaults
// for each entry, which is what makes one subject cover both checks.
func TestTheBindingsMultiEvaluationExample(t *testing.T) {
	m := mustParse(t, `{
		"evaluations": {
			"subject": { "type": "identity", "id": "$token.sub" },
			"context": { "agent": "$token.?client_id" },
			"evaluations": [
				{ "action": { "name": "read" },
				  "resource": { "type": "storage_object", "id": "$params.arguments.source" } },
				{ "action": { "name": "write" },
				  "resource": { "type": "storage_object", "id": "$params.arguments.destination" } }
			]
		}
	}`)

	got, err := resolve(t, m, map[string]any{
		"source":      "/bucket/reports/q1.pdf",
		"destination": "/bucket/archive/q1.pdf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d requests, want 2", len(got))
	}
	want := []struct{ action, id string }{
		{"read", "/bucket/reports/q1.pdf"},
		{"write", "/bucket/archive/q1.pdf"},
	}
	for i, w := range want {
		if got[i].Action.Name != w.action || got[i].Resource.ID != w.id {
			t.Errorf("request %d = %s on %s, want %s on %s", i, got[i].Action.Name, got[i].Resource.ID, w.action, w.id)
		}
		if got[i].Subject.ID != "u-8f31c02e" {
			t.Errorf("request %d subject = %q, want the sponsor", i, got[i].Subject.ID)
		}
	}
}

// An entry's member replaces the default whole: the Authorization API
// defines defaults per key, so an entry with its own context does not
// inherit the top-level one field by field.
func TestAnEntryReplacesADefaultWhole(t *testing.T) {
	m := mustParse(t, `{
		"evaluations": {
			"action": { "name": "read" },
			"context": { "purpose": "audit" },
			"evaluations": [
				{ "resource": { "type": "doc", "id": "a" } },
				{ "resource": { "type": "doc", "id": "b" }, "context": { "ticket": "T-1" } }
			]
		}
	}`)

	got, err := resolve(t, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Context["purpose"] != "audit" {
		t.Error("the first entry did not inherit the default context")
	}
	if _, ok := got[1].Context["purpose"]; ok {
		t.Error("the second entry's context was merged with the default rather than replacing it")
	}
	if got[1].Context["ticket"] != "T-1" {
		t.Error("the second entry lost its own context")
	}
	for i, r := range got {
		if r.Context["agent"] != verified().Agent {
			t.Errorf("request %d has no anchored agent", i)
		}
	}
}

// The binding's conditional example compares a JSON number, a double, with
// the integer literal 10000. Without cross-type comparison that is an error
// rather than a decision.
func TestConditionalsOverJSONNumbers(t *testing.T) {
	m := mustParse(t, `{
		"evaluation": {
			"action": { "name": "$params.arguments.currency == 'USD' ? 'domestic_transfer' : 'international_transfer'" },
			"resource": {
				"type": "account",
				"id": "$params.arguments.from_account",
				"properties": { "sensitivity": "$params.arguments.amount > 10000 ? 'high' : 'standard'" }
			}
		}
	}`)

	var args map[string]any
	if err := json.Unmarshal([]byte(`{"from_account":"acc-1","to_account":"acc-2","amount":25000,"currency":"EUR"}`), &args); err != nil {
		t.Fatal(err)
	}
	got, err := resolve(t, m, args)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Action.Name != "international_transfer" {
		t.Errorf("action.name = %q", got[0].Action.Name)
	}
	if got[0].Resource.Properties["sensitivity"] != "high" {
		t.Errorf("sensitivity = %v", got[0].Resource.Properties["sensitivity"])
	}
}

func TestLiteralsAreVerbatim(t *testing.T) {
	m := mustParse(t, `{
		"evaluation": {
			"action": { "name": "pay", "properties": { "price": "$$50", "limit": 9007199254740993, "tags": ["a", "$$b"] } },
			"resource": { "type": "invoice", "id": "inv-1" }
		}
	}`)

	got, err := resolve(t, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	props := got[0].Action.Properties
	if props["price"] != "$50" {
		t.Errorf("price = %v, want the literal $50", props["price"])
	}
	// Past 2^53 a float64 would round this to ...992.
	if n, ok := props["limit"].(json.Number); !ok || n.String() != "9007199254740993" {
		t.Errorf("limit = %v (%T), want the literal number unchanged", props["limit"], props["limit"])
	}
	if !reflect.DeepEqual(props["tags"], []any{"a", "$b"}) {
		t.Errorf("tags = %v", props["tags"])
	}
}

func TestOptionalSelectionOmitsAndPlainSelectionFails(t *testing.T) {
	m := mustParse(t, `{
		"evaluation": {
			"action": { "name": "read" },
			"resource": { "type": "doc", "id": "d", "properties": { "region": "$params.arguments.?region" } }
		}
	}`)
	got, err := resolve(t, m, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[0].Resource.Properties["region"]; ok {
		t.Error("an absent optional produced a field")
	}

	m = mustParse(t, `{
		"evaluation": {
			"action": { "name": "read" },
			"resource": { "type": "doc", "id": "d", "properties": { "region": "$params.arguments.region" } }
		}
	}`)
	_, err = resolve(t, m, map[string]any{})
	isMappingError(t, err)
}

// The token is the chain. Every claim an expression can read was established
// by verification.
func TestTheTokenIsWhatTheChainEstablished(t *testing.T) {
	m := mustParse(t, `{
		"evaluation": {
			"action": { "name": "read", "properties": {
				"iss": "$token.iss",
				"stepped_up": "$token.amr.exists(m, m == 'hwk')",
				"auth_time": "$token.auth_time"
			} },
			"resource": { "type": "doc", "id": "$params.name" }
		}
	}`)
	got, err := resolve(t, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	props := got[0].Action.Properties
	if props["iss"] != "https://idp.example.org" || props["stepped_up"] != true || props["auth_time"] != int64(1789199400) {
		t.Errorf("properties = %v", props)
	}
	if got[0].Resource.ID != "tool" {
		t.Errorf("resource.id = %q, want params.name", got[0].Resource.ID)
	}
}

// The identities in the request come from verification. A mapping may leave
// them out and have them supplied; it may not name someone else.
func TestAMappingCannotNameAnotherIdentity(t *testing.T) {
	cases := map[string]string{
		"subject.id literal":    `"subject": { "id": "u-somebody-else" }`,
		"subject.id argument":   `"subject": { "id": "$params.arguments.user" }`,
		"subject issuer":        `"subject": { "properties": { "iss": "https://evil.example" } }`,
		"agent":                 `"context": { "agent": "spiffe://example.org/ns/agents/other" }`,
		"delegation":            `"context": { "mandatum.delegation": { "depth": 0 } }`,
		"subject.id not string": `"subject": { "id": 42 }`,
	}
	for name, member := range cases {
		t.Run(name, func(t *testing.T) {
			m := mustParse(t, `{ "evaluation": {
				"action": { "name": "read" },
				"resource": { "type": "doc", "id": "d" },
				`+member+` } }`)
			_, err := resolve(t, m, map[string]any{"user": "u-somebody-else"})
			isMappingError(t, err)
		})
	}
}

func TestOmittedIdentitiesAreSupplied(t *testing.T) {
	m := mustParse(t, `{ "evaluation": {
		"action": { "name": "read" },
		"resource": { "type": "doc", "id": "d" }
	} }`)
	got, err := resolve(t, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := got[0]
	if r.Subject.Type != "identity" || r.Subject.ID != "u-8f31c02e" || r.Subject.Properties["iss"] != "https://idp.example.org" {
		t.Errorf("subject = %+v, want the sponsor supplied", r.Subject)
	}
	if r.Context["agent"] != verified().Agent {
		t.Errorf("context.agent = %v, want the acting agent supplied", r.Context["agent"])
	}
}

func TestMalformedMappingsAreRefusedAtParse(t *testing.T) {
	cases := map[string]string{
		"not an object":         `[]`,
		"no envelope":           `{}`,
		"two envelopes":         `{"evaluation": {}, "evaluations": {}}`,
		"unknown envelope":      `{"decision": {}}`,
		"trailing data":         `{"evaluation": {}} {}`,
		"unknown member":        `{"evaluation": {"action": {"name": "a"}, "resource": {"type": "t", "id": "i"}, "policy": "allow"}}`,
		"options":               `{"evaluations": {"options": {"evaluations_semantic": "permit_on_first_permit"}, "evaluations": [{"action": {"name": "a"}, "resource": {"type": "t", "id": "i"}}]}}`,
		"empty evaluations":     `{"evaluations": {"evaluations": []}}`,
		"subject in an entry":   `{"evaluations": {"evaluations": [{"subject": {"id": "u-other"}, "action": {"name": "a"}, "resource": {"type": "t", "id": "i"}}]}}`,
		"does not compile":      `{"evaluation": {"action": {"name": "$params.("}, "resource": {"type": "t", "id": "i"}}}`,
		"unknown variable":      `{"evaluation": {"action": {"name": "$request.method"}, "resource": {"type": "t", "id": "i"}}}`,
		"bare dollar":           `{"evaluation": {"action": {"name": "$"}, "resource": {"type": "t", "id": "i"}}}`,
		"entry not an object":   `{"evaluations": {"evaluations": ["read"]}}`,
		"evaluation not object": `{"evaluation": "read"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := authzen.ParseMapping([]byte(raw))
			isMappingError(t, err)
		})
	}
}

func TestResolutionFailuresAreMappingErrors(t *testing.T) {
	cases := map[string]string{
		"missing action":           `{"evaluation": {"resource": {"type": "t", "id": "i"}}}`,
		"absent required resource": `{"evaluation": {"action": {"name": "a"}, "resource": {"type": "t", "id": "$params.arguments.?id"}}}`,
		"null resource id":         `{"evaluation": {"action": {"name": "a"}, "resource": {"type": "t", "id": "$null"}}}`,
		"empty action name":        `{"evaluation": {"action": {"name": "$''"}, "resource": {"type": "t", "id": "i"}}}`,
		"no JSON form":             `{"evaluation": {"action": {"name": "a", "properties": {"b": "$b'x'"}}, "resource": {"type": "t", "id": "i"}}}`,
		"NaN":                      `{"evaluation": {"action": {"name": "a", "properties": {"n": "$0.0 / 0.0"}}, "resource": {"type": "t", "id": "i"}}}`,
		"absent inside an array":   `{"evaluation": {"action": {"name": "a", "properties": {"l": ["$params.arguments.?x"]}}, "resource": {"type": "t", "id": "i"}}}`,
		"unknown resource member":  `{"evaluation": {"action": {"name": "a"}, "resource": {"type": "t", "id": "i", "owner": "me"}}}`,
		"properties not an object": `{"evaluation": {"action": {"name": "a", "properties": "$'x'"}, "resource": {"type": "t", "id": "i"}}}`,
		"entry missing resource":   `{"evaluations": {"action": {"name": "a"}, "evaluations": [{"resource": {"type": "t", "id": "i"}}, {"context": {}}]}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			m := mustParse(t, raw)
			_, err := resolve(t, m, map[string]any{})
			isMappingError(t, err)
		})
	}
}

// A declared mapping is code written by the server being authorized. One
// that would run for a long time on every call is stopped, not waited for.
func TestAnExpensiveExpressionIsStopped(t *testing.T) {
	m := mustParse(t, `{"evaluation": {
		"action": { "name": "$params.arguments.xs.all(x, params.arguments.xs.all(y, x == x)) ? 'a' : 'b'" },
		"resource": { "type": "t", "id": "i" }
	}}`)
	xs := make([]any, 2000)
	for i := range xs {
		xs[i] = float64(i)
	}
	_, err := resolve(t, m, map[string]any{"xs": xs})
	isMappingError(t, err)
	if !strings.Contains(err.Error(), "cost") {
		t.Errorf("error = %v, want the cost limit named", err)
	}
}

// The cost limit bounds evaluating, not what evaluating produces: CEL
// charges for referencing a list, not for its length. This mapping is cheap
// in CEL and, unbounded, is a hundred copies of a 200,000-element list — about
// two gigabytes allocated, from arguments under half a megabyte.
func TestAnAmplifyingExpressionIsStopped(t *testing.T) {
	m := mustParse(t, `{"evaluation": {
		"action": { "name": "a", "properties": { "x": "$params.arguments.k.map(x, params.arguments.l)" } },
		"resource": { "type": "t", "id": "i" }
	}}`)
	l := make([]any, 200_000)
	k := make([]any, 100)
	for i := range l {
		l[i] = float64(0)
	}
	for i := range k {
		k[i] = float64(0)
	}
	_, err := resolve(t, m, map[string]any{"k": k, "l": l})
	isMappingError(t, err)
	if !strings.Contains(err.Error(), "values") {
		t.Errorf("error = %v, want the size bound named", err)
	}
}

// Go's encoding/json matches keys case-insensitively, with Unicode folding,
// and takes the last match. `iſſ` (U+017F) folds to `iss` and sorts after it,
// so a PDP decoding into a struct would read the twin, not the anchor.
func TestAFoldTwinOfAnAnchoredKeyIsRefused(t *testing.T) {
	cases := map[string]string{
		"long s":    `"subject": { "properties": { "iſſ": "https://evil.example" } }`,
		"upper iss": `"subject": { "properties": { "ISS": "https://evil.example" } }`,
		"agent":     `"context": { "Agent": "spiffe://example.org/ns/agents/other" }`,
		"chain":     `"context": { "Mandatum.Delegation": {} }`,
	}
	for name, member := range cases {
		t.Run(name, func(t *testing.T) {
			m := mustParse(t, `{ "evaluation": {
				"action": { "name": "read" },
				"resource": { "type": "doc", "id": "d" },
				`+member+` } }`)
			_, err := resolve(t, m, nil)
			isMappingError(t, err)
		})
	}
}

func TestMappingFromInputSchema(t *testing.T) {
	m, err := authzen.MappingFromInputSchema([]byte(`{
		"type": "object",
		"properties": { "id": { "type": "string" } },
		"x-authzen-mapping": { "evaluation": { "action": { "name": "get" }, "resource": { "type": "t", "id": "$params.arguments.id" } } }
	}`))
	if err != nil || m == nil {
		t.Fatalf("got %v, %v; want a mapping", m, err)
	}

	m, err = authzen.MappingFromInputSchema([]byte(`{"type": "object"}`))
	if err != nil || m != nil {
		t.Errorf("got %v, %v; want no mapping, so the default applies", m, err)
	}

	_, err = authzen.MappingFromInputSchema([]byte(`{"x-authzen-mapping": {"evaluation": "read"}}`))
	isMappingError(t, err)
}

// Whatever a mapping says, a request it resolves to carries the chain's
// identities and nobody else's, and is one the client can send. A mapping
// that cannot honour that has to fail as a mapping error, never panic and
// never produce a request.
func FuzzDeclaredMapping(f *testing.F) {
	f.Add(`{"evaluation":{"subject":{"type":"identity","id":"$token.sub"},"action":{"name":"get_customer"},"resource":{"type":"customer","id":"$params.arguments.id"},"context":{"agent":"$token.?client_id","case":"$params.arguments.case"}}}`,
		`{"id":"cust-12345","case":"case-67890"}`)
	f.Add(`{"evaluations":{"subject":{"id":"$token.sub"},"evaluations":[{"action":{"name":"read"},"resource":{"type":"o","id":"$params.arguments.source"}},{"action":{"name":"write"},"resource":{"type":"o","id":"$params.arguments.destination"}}]}}`,
		`{"source":"/a","destination":"/b"}`)
	f.Add(`{"evaluation":{"subject":{"id":"$params.arguments.u"},"action":{"name":"$params.arguments.amount > 10000 ? 'a' : 'b'"},"resource":{"type":"$$t","id":"$string(params.arguments.amount)"},"context":{"agent":"$token.client_id"}}}`,
		`{"u":"u-8f31c02e","amount":12345}`)

	f.Fuzz(func(t *testing.T, mapping, arguments string) {
		m, err := authzen.ParseMapping([]byte(mapping))
		if err != nil {
			var me *authzen.MappingError
			if !errors.As(err, &me) {
				t.Fatalf("ParseMapping failed with %T, not a mapping error: %v", err, err)
			}
			return
		}
		var args map[string]any
		if json.Unmarshal([]byte(arguments), &args) != nil {
			args = nil
		}

		want := verified()
		requests, err := m.ToolCallRequests(context.Background(), want, authzen.ToolCall{Name: "tool", Arguments: args})
		if err != nil {
			var me *authzen.MappingError
			if !errors.As(err, &me) {
				t.Fatalf("resolution failed with %T, not a mapping error: %v", err, err)
			}
			return
		}
		if len(requests) == 0 {
			t.Fatal("a mapping resolved to no request, which would allow the call unasked")
		}
		for i, r := range requests {
			if r.Subject.ID != want.Sponsor.Subject || r.Subject.Properties["iss"] != want.Sponsor.Issuer {
				t.Fatalf("request %d subject = %+v, not the sponsor", i, r.Subject)
			}
			for key := range r.Subject.Properties {
				if key != "iss" && strings.EqualFold(key, "iss") {
					t.Fatalf("request %d carries %q beside the anchored iss", i, key)
				}
			}
			for key := range r.Context {
				for _, anchor := range []string{"agent", authzen.DelegationContextKey} {
					if key != anchor && strings.EqualFold(key, anchor) {
						t.Fatalf("request %d carries %q beside the anchored %s", i, key, anchor)
					}
				}
			}
			if r.Context["agent"] != want.Agent {
				t.Fatalf("request %d context.agent = %v, not the acting agent", i, r.Context["agent"])
			}
			if d, ok := r.Context[authzen.DelegationContextKey].(authzen.Delegation); !ok || d.Chain != want.ChainDigest {
				t.Fatalf("request %d does not carry the verified chain", i)
			}
			if r.Subject.Type == "" || r.Action.Name == "" || r.Resource.Type == "" || r.Resource.ID == "" {
				t.Fatalf("request %d is incomplete: %+v", i, r)
			}
			if _, err := json.Marshal(r); err != nil {
				t.Fatalf("request %d does not encode: %v", i, err)
			}
		}
	})
}
