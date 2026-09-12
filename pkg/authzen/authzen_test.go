package authzen_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/mandatum/pkg/authzen"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/verify"
)

func request() authzen.Request {
	return authzen.Request{
		Subject:  authzen.Subject{Type: "identity", ID: "u-8f31c02e"},
		Action:   authzen.Action{Name: "tools/call"},
		Resource: authzen.Resource{Type: "tool", ID: "search.query"},
	}
}

// clientFor wraps the handler so that it echoes X-Request-ID, which a
// conformant PDP must do. Tests that care about a missing echo use
// rawClientFor and omit it deliberately.
func clientFor(t *testing.T, h http.HandlerFunc, opts ...authzen.Option) *authzen.Client {
	t.Helper()
	return rawClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get("X-Request-ID"); id != "" {
			w.Header().Set("X-Request-ID", id)
		}
		h(w, r)
	}, opts...)
}

func rawClientFor(t *testing.T, h http.HandlerFunc, opts ...authzen.Option) *authzen.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := authzen.New(srv.URL+"/access/v1/evaluation", opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestEvaluateAllows(t *testing.T) {
	var got authzen.Request
	c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if r.Header.Get("X-Request-ID") == "" {
			t.Error("no X-Request-ID; the decision cannot be correlated across PEP and PDP logs")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("X-Request-ID", r.Header.Get("X-Request-ID"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true}`))
	})

	d, err := c.Evaluate(context.Background(), request())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.Allowed {
		t.Error("decision denied an allow response")
	}
	if got.Subject.ID != "u-8f31c02e" || got.Resource.ID != "search.query" {
		t.Errorf("PDP received %+v", got)
	}
}

func TestEvaluateCarriesTheDenialReason(t *testing.T) {
	c := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":false,"context":{"reason_user":{"403":"Insufficient privileges"}}}`))
	})

	d, err := c.Evaluate(context.Background(), request())
	if err != nil {
		t.Fatalf("a well-formed deny is not an error: %v", err)
	}
	if d.Allowed {
		t.Fatal("allowed a deny response")
	}
	if d.Context["reason_user"] == nil {
		t.Error("the reason did not reach the caller, so nobody can answer 'why was this denied?'")
	}
}

// Every one of these is a way an evaluation can fail to complete. Each must
// deny, and must deny through the returned Decision as well as the error, so
// that a caller who checks only one of the two still denies.
func TestEverythingThatCanGoWrongDenies(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		opts    []authzen.Option
		want    string
	}{
		{
			name: "PDP returns 500",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"boom"}`))
			},
			want: "returned 500",
		},
		{
			name: "PDP returns 403",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			want: "returned 403",
		},
		{
			name: "body is not JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`not json`))
			},
			want: "decoding the decision",
		},
		{
			name: "body carries a field this PEP does not understand",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"decision":true,"obligations":["encrypt"]}`))
			},
			want: "decoding the decision",
		},
		{
			name:    "empty body",
			handler: func(w http.ResponseWriter, _ *http.Request) {},
			want:    "decoding the decision",
		},
		{
			name: "the answer belongs to a different request",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Request-ID", "some-other-request")
				_, _ = w.Write([]byte(`{"decision":true}`))
			},
			want: "may belong to another request",
		},
		{
			name: "the PDP never answers",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(300 * time.Millisecond)
				_, _ = w.Write([]byte(`{"decision":true}`))
			},
			opts: []authzen.Option{authzen.WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond})},
			want: "reaching the PDP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clientFor(t, tt.handler, tt.opts...)

			d, err := c.Evaluate(context.Background(), request())
			if err == nil {
				t.Fatal("no error reported")
			}
			if d.Allowed {
				t.Fatal("the returned Decision allowed; a caller ignoring the error would permit the action")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// A PDP that omits the echo has not established that its answer belongs to
// this question, which is the same thing a mismatch means. Denying only on a
// mismatch would let a cache or a proxy defeat the check by dropping one
// header, so both are denials.
func TestAMissingRequestIDEchoDenies(t *testing.T) {
	c := rawClientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"decision":true}`))
	})

	d, err := c.Evaluate(context.Background(), request())
	if err == nil {
		t.Fatal("accepted a decision that could not be tied to the request")
	}
	if d.Allowed {
		t.Fatal("the returned Decision allowed")
	}
	if !strings.Contains(err.Error(), "cannot be tied to this request") {
		t.Errorf("unexpected reason: %v", err)
	}
}

// Sending no identifier is the explicit way to work with a PDP that does not
// echo. It is visible at the call site, unlike a client that quietly accepts
// uncorrelated answers.
func TestNoRequestIDMeansNoCorrelationCheck(t *testing.T) {
	c := rawClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Request-ID"); got != "" {
			t.Errorf("sent X-Request-ID %q despite an empty generator", got)
		}
		_, _ = w.Write([]byte(`{"decision":true}`))
	}, authzen.WithRequestID(func() string { return "" }))

	d, err := c.Evaluate(context.Background(), request())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.Allowed {
		t.Error("denied an allow response")
	}
}

func TestEvaluateRejectsIncompleteRequests(t *testing.T) {
	c := clientFor(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("an incomplete request reached the PDP")
	})

	tests := map[string]func(*authzen.Request){
		"no subject type": func(r *authzen.Request) { r.Subject.Type = "" },
		"no subject id":   func(r *authzen.Request) { r.Subject.ID = "" },
		"no resource id":  func(r *authzen.Request) { r.Resource.ID = "" },
		"no action name":  func(r *authzen.Request) { r.Action.Name = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := request()
			mutate(&r)
			d, err := c.Evaluate(context.Background(), r)
			if err == nil {
				t.Fatal("accepted an incomplete request")
			}
			if d.Allowed {
				t.Error("returned an allowing decision")
			}
		})
	}
}

func TestNewRejectsUnusableConfiguration(t *testing.T) {
	if _, err := authzen.New("http://pdp.example.org/access/v1/evaluation"); err == nil {
		t.Error("accepted a plaintext endpoint; an evaluation carries the subject's identity")
	}
	if _, err := authzen.New("://nonsense"); err == nil {
		t.Error("accepted an unparsable endpoint")
	}
	if _, err := authzen.New("https://pdp.example.org/access/v1/evaluation",
		authzen.WithHTTPClient(&http.Client{})); err == nil {
		t.Error("accepted a client with no timeout")
	}
	if _, err := authzen.New("http://localhost:9999/access/v1/evaluation"); err != nil {
		t.Errorf("rejected a loopback endpoint, which development needs: %v", err)
	}
}

func TestDiscover(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != authzen.WellKnownPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{
			"policy_decision_point": "` + srv.URL + `",
			"access_evaluation_endpoint": "` + srv.URL + `/access/v1/evaluation",
			"a_parameter_this_pep_does_not_know": true
		}`))
	}))
	defer srv.Close()

	m, err := authzen.Discover(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if m.AccessEvaluationEndpoint != srv.URL+"/access/v1/evaluation" {
		t.Errorf("endpoint = %q", m.AccessEvaluationEndpoint)
	}
}

// A metadata document claiming to belong to a different PDP is the mix-up
// attack the identifier exists to prevent.
func TestDiscoverRejectsAMismatchedIdentifier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"policy_decision_point": "https://attacker.example.org",
			"access_evaluation_endpoint": "https://attacker.example.org/access/v1/evaluation"
		}`))
	}))
	defer srv.Close()

	m, err := authzen.Discover(context.Background(), srv.URL, srv.Client())
	if err == nil {
		t.Fatal("accepted metadata declaring a different PDP")
	}
	if m.AccessEvaluationEndpoint != "" {
		t.Error("returned an endpoint from rejected metadata")
	}
	if !strings.Contains(err.Error(), "declares PDP") {
		t.Errorf("unexpected reason: %v", err)
	}
}

func TestDiscoverRejectsMetadataWithoutAnEndpoint(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"policy_decision_point": "` + srv.URL + `"}`))
	}))
	defer srv.Close()

	if _, err := authzen.Discover(context.Background(), srv.URL, srv.Client()); err == nil {
		t.Fatal("accepted metadata with no access_evaluation_endpoint")
	}
}

func TestToolCallRequestFollowsTheCoazMapping(t *testing.T) {
	res := &verify.Result{
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
	call := authzen.ToolCall{
		Name:      "search.query",
		Arguments: map[string]any{"index": "public"},
		Server:    "https://mcp.example.org",
	}

	req := authzen.ToolCallRequest(res, call)

	// COAZ-MCP puts the human in subject and the acting client in
	// context.agent. Getting this backwards would attribute every action to
	// the agent and lose the human entirely.
	if req.Subject.Type != "identity" || req.Subject.ID != "u-8f31c02e" {
		t.Errorf("subject = %+v, want the human sponsor as type identity", req.Subject)
	}
	if req.Subject.Properties["iss"] != "https://idp.example.org" {
		t.Error("the sponsor's issuer is missing; subject ids are only unique within an issuer")
	}
	if req.Context["agent"] != res.Agent {
		t.Errorf("context.agent = %v, want the acting agent", req.Context["agent"])
	}
	if req.Action.Name != "tools/call" {
		t.Errorf("action = %q", req.Action.Name)
	}
	if req.Resource.Type != "tool" || req.Resource.ID != "search.query" {
		t.Errorf("resource = %+v", req.Resource)
	}
	if req.Resource.Properties["server"] != call.Server {
		t.Error("the server is missing from the resource")
	}

	d, ok := req.Context[authzen.DelegationContextKey].(authzen.Delegation)
	if !ok {
		t.Fatalf("no delegation in context under %q", authzen.DelegationContextKey)
	}
	if d.Chain != res.ChainDigest {
		t.Errorf("chain digest = %q", d.Chain)
	}
	if len(d.Actors) != 2 || d.Actors[1] != res.Agent {
		t.Errorf("actors = %v, want the chain from the sponsor's grantee to the acting agent", d.Actors)
	}
	if d.Leaf != "jti-child" {
		t.Errorf("leaf = %q; without it a PDP cannot tell an operator what to revoke", d.Leaf)
	}
	if d.Sponsor.AuthenticatedAt != 1789199400 || len(d.Sponsor.Methods) != 2 {
		t.Error("sponsor authentication details are missing; policy cannot require step-up without them")
	}
}

// The mapped request has to survive JSON, since that is how it reaches a PDP.
func TestToolCallRequestSerializes(t *testing.T) {
	res := &verify.Result{
		Sponsor:     mda.Sponsor{Issuer: "https://idp.example.org", Subject: "u-1"},
		Agent:       "agent-b",
		Actors:      []string{"agent-a", "agent-b"},
		ChainDigest: "sha-256:abc",
		LeafID:      "jti-b",
	}
	raw, err := json.Marshal(authzen.ToolCallRequest(res, authzen.ToolCall{Name: "t"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"type":"identity"`, `"id":"u-1"`, `"name":"tools/call"`,
		`"type":"tool"`, `"agent":"agent-b"`, `"mandatum.delegation"`, `"actors":["agent-a","agent-b"]`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("serialized request is missing %s\n%s", want, raw)
		}
	}
}
