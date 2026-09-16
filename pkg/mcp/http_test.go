package mcp_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kanywst/mandatum/pkg/mcp"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/sequence"
)

// quiet keeps the denial log out of the test output. A deployment gets
// slog.Default(); these tests assert on the response, not the log.
func quiet() mcp.Option {
	return mcp.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func middleware(t *testing.T, w *world, decider mcp.Decider, opts ...mcp.Option) (http.Handler, *spy) {
	t.Helper()
	evaluator, err := sequence.NewEvaluator(sequence.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	e, err := mcp.New(w.verifier(), catalog, decider, evaluator, append([]mcp.Option{quiet()}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	s := &spy{}
	return e.Middleware(s), s
}

// spy is the MCP server behind the middleware. It records whether it was
// reached and what body arrived, because a middleware that authorizes
// correctly and then forwards a drained body is still broken.
type spy struct {
	called int
	body   string
}

func (s *spy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.called++
	body, _ := io.ReadAll(r.Body)
	s.body = string(body)
	w.WriteHeader(http.StatusOK)
}

// toolCall renders a JSON-RPC tools/call request carrying chain in _meta.
func toolCall(tool string, chain mda.Chain) string {
	links := make([]string, 0, len(chain))
	for _, link := range chain {
		links = append(links, string(link.Raw))
	}
	meta, err := json.Marshal(map[string]any{mcp.ChainMetaKey: links})
	if err != nil {
		panic(err)
	}
	params, err := json.Marshal(map[string]any{
		"name":      tool,
		"arguments": map[string]any{},
		"_meta":     json.RawMessage(meta),
	})
	if err != nil {
		panic(err)
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params":  json.RawMessage(params),
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// refusal reads the JSON-RPC error a denied call comes back as.
func refusal(t *testing.T, rec *httptest.ResponseRecorder) (code int, stage string) {
	t.Helper()
	var response struct {
		Error struct {
			Code int            `json:"code"`
			Data map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("the refusal is not a JSON-RPC error response: %v (%s)", err, rec.Body)
	}
	got, _ := response.Error.Data["stage"].(string)
	return response.Error.Code, got
}

func TestMiddlewareForwardsAnAuthorizedCallWithItsBodyIntact(t *testing.T) {
	w := newWorld(t)
	h, server := middleware(t, w, &pdp{allow: true})

	body := toolCall("search.query", w.chain(nil))
	rec := post(h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if server.called != 1 {
		t.Fatalf("the server was called %d times, want 1", server.called)
	}
	if server.body != body {
		t.Error("the server received a different body than the client sent; the request was drained reading the envelope")
	}
}

func TestMiddlewareRefusesACallOutsideTheGrant(t *testing.T) {
	w := newWorld(t)
	h, server := middleware(t, w, &pdp{allow: true})

	rec := post(h, toolCall("admin.wipeAll", w.chain(nil)))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	code, stage := refusal(t, rec)
	if code != mcp.CodeDenied {
		t.Errorf("error code = %d, want %d", code, mcp.CodeDenied)
	}
	if stage != string(mcp.StagePermits) {
		t.Errorf("stage = %q, want %q", stage, mcp.StagePermits)
	}
	if server.called != 0 {
		t.Error("a refused call reached the server")
	}
}

// The reason names the rule, the capability or the constraint that refused.
// It goes to the operator's log; the caller gets the stage and no more,
// because an agent under an attacker's control would otherwise be able to
// search for a call that is not refused.
func TestARefusalDoesNotTellTheCallerWhy(t *testing.T) {
	w := newWorld(t)
	h, _ := middleware(t, w, &pdp{allow: true})

	rec := post(h, toolCall("admin.wipeAll", w.chain(nil)))

	if body := rec.Body.String(); strings.Contains(body, "admin.wipeAll") || strings.Contains(body, "outside the chain's grant") {
		t.Errorf("the response repeats the denial reason to the caller: %s", body)
	}
}

func TestMiddlewareForwardsMethodsItDoesNotEnforce(t *testing.T) {
	w := newWorld(t)
	h, server := middleware(t, w, &pdp{allow: false})

	rec := post(h, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if server.called != 1 {
		t.Error("tools/list was not forwarded; this middleware enforces tools/call and nothing else")
	}
}

func TestMiddlewareRefusesWhatItCannotRead(t *testing.T) {
	w := newWorld(t)

	for _, tc := range []struct{ name, body string }{
		{"not JSON", `{"jsonrpc":`},
		// A batch. Its members are not examined individually here, so it
		// must not pass as though they had been.
		{"a batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search.query"}}]`},
		{"tools/call with no params", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`},
		{"tools/call with no chain", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search.query"}}`},
		{"a chain that is not an array", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search.query","_meta":{"` + mcp.ChainMetaKey + `":"not-an-array"}}}`},
		{"an empty chain", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search.query","_meta":{"` + mcp.ChainMetaKey + `":[]}}}`},
		{"a chain that is not an assertion", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search.query","_meta":{"` + mcp.ChainMetaKey + `":["not.a.jws"]}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, server := middleware(t, w, &pdp{allow: true})
			rec := post(h, tc.body)

			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
			if server.called != 0 {
				t.Error("a request the middleware could not read was forwarded anyway")
			}
		})
	}
}

func TestMiddlewareRefusesABodyOverTheLimit(t *testing.T) {
	w := newWorld(t)
	h, server := middleware(t, w, &pdp{allow: true}, mcp.WithMaxBodyBytes(64))

	rec := post(h, toolCall("search.query", w.chain(nil)))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if server.called != 0 {
		t.Error("an oversized body was forwarded")
	}
}
