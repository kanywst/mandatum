// Package authzen speaks the OpenID AuthZEN Authorization API 1.0.
//
// It is a client, not an engine. Mandatum establishes that an agent holds a
// valid delegation chain; this package asks a Policy Decision Point whether
// the action that chain permits is one organizational policy also permits.
// The two questions are separate on purpose: verification bounds what any
// answer can mean, so a compromised PDP can deny anything but cannot grant
// authority no sponsor delegated.
//
// Everything here fails closed. A transport error, a timeout, a non-200
// status, a body that does not parse — each denies. The API returns a
// concrete Decision alongside its error precisely so that a caller who
// ignores the error still denies rather than reading a zero value as
// permission.
//
// Reference: OpenID AuthZEN Authorization API 1.0, Final Specification,
// 11 January 2026.
package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Subject is the principal on whose behalf access is requested.
//
// Under the COAZ-MCP binding this is the human, not the agent: the acting
// agent goes in the request context. Mandatum follows that, which is what
// makes a chain rooted in a sponsor map onto the API without inventing
// anything.
type Subject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is the target of the access request.
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is the access being attempted.
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Request is an Access Evaluation request.
type Request struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// Decision is an Access Evaluation response.
//
// The specification defines exactly two outcomes, so this is a boolean and
// not an enum with room for a third state that a PEP would have to guess at.
type Decision struct {
	// Allowed is the spec's `decision`. False denies.
	Allowed bool `json:"decision"`
	// Context carries whatever the PDP chose to explain itself with:
	// reasons, obligations, step-up instructions. The specification leaves
	// its shape open, so it is not typed further here.
	Context map[string]any `json:"context,omitempty"`
}

// Deny is the decision returned whenever an evaluation cannot be completed.
// It is a value rather than a zero struct so that the intent is legible at
// every return site.
var Deny = Decision{Allowed: false}

// Client evaluates access against one PDP.
type Client struct {
	endpoint string
	http     *http.Client
	headers  http.Header
	newID    func() string
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the HTTP client. The client's timeout is respected
// as-is; a client with no timeout is rejected by New, because an evaluation
// that never returns is an enforcement point that never answers.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithHeader adds a header to every request, for the authentication a
// deployment's PDP expects. The Authorization API does not mandate one.
func WithHeader(name, value string) Option {
	return func(c *Client) { c.headers.Set(name, value) }
}

// WithRequestID replaces the request-identifier generator. The specification
// recommends X-Request-ID and requires the PDP to echo it, which is what
// makes a decision traceable across the PEP and PDP logs.
func WithRequestID(gen func() string) Option {
	return func(c *Client) { c.newID = gen }
}

// DefaultTimeout applies when the caller supplies no HTTP client.
const DefaultTimeout = 3 * time.Second

// New returns a Client for the given Access Evaluation endpoint.
//
// The endpoint is the full URL, conventionally ending in /access/v1/evaluation.
// Discover it from PDP metadata rather than assembling it by hand where the
// PDP publishes metadata; see Discover.
func New(endpoint string, opts ...Option) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("authzen: parsing endpoint: %w", err)
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return nil, fmt.Errorf(
			"authzen: endpoint %q is not https; an evaluation carries the subject's identity", endpoint)
	}

	c := &Client{
		endpoint: endpoint,
		http:     &http.Client{Timeout: DefaultTimeout},
		headers:  http.Header{},
		newID:    randomID,
	}
	for _, o := range opts {
		o(c)
	}
	if c.http.Timeout == 0 {
		return nil, errors.New(
			"authzen: the HTTP client has no timeout; an evaluation that never returns is an enforcement point that never answers")
	}
	return c, nil
}

// Evaluate asks the PDP about one access request.
//
// A non-nil error always accompanies a denying Decision. Callers should treat
// the Decision as authoritative and the error as the explanation, so that
// forgetting to check one of the two still denies.
func (c *Client) Evaluate(ctx context.Context, r Request) (Decision, error) {
	if err := r.validate(); err != nil {
		return Deny, err
	}

	body, err := json.Marshal(r)
	if err != nil {
		return Deny, fmt.Errorf("authzen: encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Deny, fmt.Errorf("authzen: building request: %w", err)
	}
	for k, v := range c.headers {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	requestID := c.newID()
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Deny, fmt.Errorf("authzen: reaching the PDP: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded read: a PDP that streams without end must not exhaust the
	// enforcement point's memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Deny, fmt.Errorf("authzen: reading the PDP response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Deny, &StatusError{
			Status:    resp.StatusCode,
			RequestID: resp.Header.Get("X-Request-ID"),
			Body:      strings.TrimSpace(string(raw)),
		}
	}

	// The PDP MUST echo the request identifier when the PEP sends one. A
	// mismatch means the answer may belong to a different question; a
	// missing echo means the same thing, since correlation was never
	// established. Accepting the second while denying the first would let a
	// cache or proxy defeat the check by dropping one header.
	if requestID != "" {
		switch echoed := resp.Header.Get("X-Request-ID"); {
		case echoed == "":
			return Deny, fmt.Errorf(
				"authzen: response carries no request id, expected %q; "+
					"this answer cannot be tied to this request", requestID)
		case echoed != requestID:
			return Deny, fmt.Errorf(
				"authzen: response carries request id %q, expected %q; "+
					"this answer may belong to another request", echoed, requestID)
		}
	}

	var d Decision
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		// An unrecognised field may be a newer response element that changes
		// how the decision should be read. The specification permits a PEP
		// to reject a decision whose context it does not understand, and
		// this takes that permission.
		return Deny, fmt.Errorf("authzen: decoding the decision: %w", err)
	}
	return d, nil
}

const maxResponseBytes = 1 << 20

// StatusError reports a PDP response that was not 200 OK.
type StatusError struct {
	Status    int
	RequestID string
	Body      string
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("authzen: PDP returned %d", e.Status)
	if e.RequestID != "" {
		msg += fmt.Sprintf(" (request %s)", e.RequestID)
	}
	if e.Body != "" {
		msg += ": " + truncate(e.Body, 200)
	}
	return msg
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (r Request) validate() error {
	switch {
	case r.Subject.Type == "" || r.Subject.ID == "":
		return errors.New("authzen: subject requires both type and id")
	case r.Resource.Type == "" || r.Resource.ID == "":
		return errors.New("authzen: resource requires both type and id")
	case r.Action.Name == "":
		return errors.New("authzen: action requires a name")
	}
	return nil
}
