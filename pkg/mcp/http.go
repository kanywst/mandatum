package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/kanywst/mandatum/pkg/mda"
)

// ChainMetaKey is the `_meta` key a delegation chain travels in on a
// `tools/call` request. Its value is the chain's compact serializations as a
// JSON array of strings, sponsor's grant first — the same order and the same
// encoding mda.ParseChain reads.
//
// MCP reserves `_meta` for exactly this, and constrains the key: a prefix is
// a series of dot-separated labels followed by a slash, implementations
// SHOULD use reverse DNS notation, and any prefix whose second label is
// `modelcontextprotocol` or `mcp` is reserved for MCP itself. This one is
// reverse DNS for the project's own domain and its second label is `github`,
// so it is a third-party key and cannot be mistaken for a protocol one.
//
// Reference: Model Context Protocol, revision 2026-07-28, "General fields:
// `_meta`".
const ChainMetaKey = "io.github.kanywst.mandatum/chain"

// ToolCallMethod is the JSON-RPC method this middleware enforces.
const ToolCallMethod = "tools/call"

// CodeDenied is the JSON-RPC error code returned for a refused call.
//
// MCP partitions the implementation-defined range `-32000` to `-32099`
// between codes allocated before its policy existed and codes reserved for
// the specification, and says new codes for purposes the specification does
// not define SHOULD be allocated outside the JSON-RPC reserved range
// entirely. This is outside it, and matches the HTTP status sent with it.
const CodeDenied = 403

// DefaultMaxBodyBytes bounds the request body the middleware will read. A
// tool call carrying a delegation chain is kilobytes; anything approaching
// this is not one.
const DefaultMaxBodyBytes int64 = 1 << 20

// WithMaxBodyBytes bounds how much of a request body the middleware reads
// before refusing it.
func WithMaxBodyBytes(n int64) Option {
	return func(e *Enforcer) { e.maxBody = n }
}

// WithLogger replaces the logger denials are written to.
//
// Denials are logged with the reason the refusing check gave, which is not
// sent to the caller: an agent under an attacker's control should not be
// able to read back which rule stopped it, and an operator has to be able to
// answer why a call failed. The default is slog.Default(), because a denial
// nobody can explain is a denial that gets switched off.
func WithLogger(l *slog.Logger) Option {
	return func(e *Enforcer) { e.log = l }
}

// Middleware returns a handler that authorizes every `tools/call` passing
// through it and forwards the request to next only if Authorize allows it.
//
// Requests for other methods are forwarded unexamined. That is a statement
// of scope rather than a gap: `tools/call` is the only way to invoke a tool,
// it is the only method the COAZ-MCP binding's default mapping is
// implemented for here (see docs/spec/coaz-mcp-conformance.md), and a
// delegation chain says nothing about `tools/list` or `initialize`. What it
// does mean is that this middleware is not a substitute for MCP's own
// authorization on the transport; it is the per-call layer above it.
//
// A body this middleware cannot parse is refused rather than forwarded,
// since a request it could not read might be the tool call it exists to
// check. That includes a JSON-RPC batch: MCP messages are single objects,
// and an array whose members are not individually examined here must not
// pass as though they had been.
//
// The chain is left in `_meta` on the forwarded request. The server behind
// this has every reason to record what authorized a call, and removing it
// would take that away.
func (e *Enforcer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		max := e.maxBody
		if max <= 0 {
			max = DefaultMaxBodyBytes
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
		if err != nil {
			e.refuse(w, nil, StageVerify, "the request body could not be read", err)
			return
		}

		var envelope struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			e.refuse(w, nil, StageVerify, "the request is not a JSON-RPC message", err)
			return
		}

		if envelope.Method != ToolCallMethod {
			forward(next, w, r, body)
			return
		}

		call, err := parseToolCall(envelope.Params)
		if err != nil {
			e.refuse(w, envelope.ID, StageVerify, "the tool call could not be read", err)
			return
		}

		if _, err := e.Authorize(r.Context(), call); err != nil {
			stage := StageVerify
			if refusal, ok := Refused(err); ok {
				stage = refusal.Stage
			}
			e.refuse(w, envelope.ID, stage, "the delegation chain does not authorize this call", err)
			return
		}

		forward(next, w, r, body)
	})
}

// parseToolCall reads `params` into a Call.
//
// An absent or empty chain is an error here rather than an empty chain
// handed to the verifier. Both deny — verification rejects an empty chain —
// but only one of them says what is actually wrong with the request.
//
// `_meta` is read as a map and indexed by ChainMetaKey rather than through a
// struct tag naming the key a second time. Two spellings of one key is the
// shape of a middleware that silently stops finding chains.
func parseToolCall(params json.RawMessage) (Call, error) {
	if len(params) == 0 {
		return Call{}, errors.New("a tools/call request with no params names no tool")
	}

	var p struct {
		Name      string                     `json:"name"`
		Arguments map[string]any             `json:"arguments"`
		Meta      map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return Call{}, err
	}

	raw, ok := p.Meta[ChainMetaKey]
	if !ok {
		return Call{}, fmt.Errorf("the call carries no delegation chain at _meta[%q]", ChainMetaKey)
	}
	var links []string
	if err := json.Unmarshal(raw, &links); err != nil {
		return Call{}, fmt.Errorf("_meta[%q] is not an array of compact serializations: %w", ChainMetaKey, err)
	}
	if len(links) == 0 {
		return Call{}, errors.New("the delegation chain is empty, and an empty chain establishes nothing")
	}

	serializations := make([][]byte, 0, len(links))
	for _, link := range links {
		serializations = append(serializations, []byte(link))
	}
	chain, err := mda.ParseChain(serializations)
	if err != nil {
		return Call{}, err
	}

	return Call{Chain: chain, Tool: p.Name, Arguments: p.Arguments}, nil
}

// forward hands the request on with its body intact. The body was consumed
// to read the envelope, so it is replaced rather than reused; a handler
// reading an already-drained body would see an empty request.
func forward(next http.Handler, w http.ResponseWriter, r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	next.ServeHTTP(w, r)
}

// refuse writes a JSON-RPC error response and logs why.
//
// The caller is told the stage and nothing else. The reason names the rule,
// the capability or the constraint that refused, which is what an operator
// needs and what an agent under an attacker's control would use to search
// for a call that is not refused.
func (e *Enforcer) refuse(w http.ResponseWriter, id json.RawMessage, stage Stage, message string, cause error) {
	log := e.log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("mcp: tool call refused", "stage", string(stage), "reason", cause)

	response := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id,omitempty"`
		Error   struct {
			Code    int            `json:"code"`
			Message string         `json:"message"`
			Data    map[string]any `json:"data,omitempty"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	response.Error.Code = CodeDenied
	response.Error.Message = message
	response.Error.Data = map[string]any{"stage": string(stage)}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	// The response is a fixed shape over an already-validated id, so
	// encoding cannot fail for any reason a caller could arrange. If the
	// connection has gone away there is nothing useful left to do about it.
	_ = json.NewEncoder(w).Encode(response)
}
