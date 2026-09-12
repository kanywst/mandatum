package authzen

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownPath is where a PDP publishes its metadata, per Authorization API
// 1.0 §PDP Metadata and RFC 8615.
const WellKnownPath = "/.well-known/authzen-configuration"

// Metadata is the subset of PDP metadata this package uses. Parameters a PEP
// does not understand must be ignored, so unknown fields are dropped rather
// than rejected — the opposite of how a decision response is treated, because
// metadata cannot make an unsafe request safe.
type Metadata struct {
	// PolicyDecisionPoint is the PDP identifier. It exists to prevent mix-up
	// attacks and is checked against the URL the document was fetched from.
	PolicyDecisionPoint string `json:"policy_decision_point"`

	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint,omitempty"`
	SearchSubjectEndpoint     string `json:"search_subject_endpoint,omitempty"`
	SearchResourceEndpoint    string `json:"search_resource_endpoint,omitempty"`
	SearchActionEndpoint      string `json:"search_action_endpoint,omitempty"`
}

// Discover fetches a PDP's metadata from its issuer identifier.
//
// Using discovery rather than a hand-assembled path means a PDP that moves an
// endpoint does not silently start receiving requests at a URL that answers
// something else.
func Discover(ctx context.Context, pdp string, httpClient *http.Client) (Metadata, error) {
	var m Metadata

	u, err := url.Parse(pdp)
	if err != nil {
		return m, fmt.Errorf("authzen: parsing the PDP identifier: %w", err)
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return m, fmt.Errorf("authzen: the PDP identifier %q must use https", pdp)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return m, fmt.Errorf("authzen: the PDP identifier %q must have no query or fragment", pdp)
	}

	// RFC 8615 places the well-known segment between the host and the path.
	wellKnown := *u
	wellKnown.Path = WellKnownPath + strings.TrimSuffix(u.Path, "/")

	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	// The same guard New applies. A caller reusing one client for both would
	// otherwise get a checked evaluation and an unchecked metadata fetch.
	if err := requireTimeout(httpClient); err != nil {
		return m, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown.String(), nil)
	if err != nil {
		return m, fmt.Errorf("authzen: building the metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return m, fmt.Errorf("authzen: fetching PDP metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return m, fmt.Errorf("authzen: reading PDP metadata: %w", err)
	}
	// Read before checking the status, so a failure carries whatever the PDP
	// sent to explain itself. Evaluate does the same: an error saying only
	// "404" sends whoever is debugging back to the server logs.
	if resp.StatusCode != http.StatusOK {
		return m, &StatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("authzen: decoding PDP metadata: %w", err)
	}

	// The mix-up defence: a document served from one PDP must not claim to
	// be another's, or a PEP can be steered into asking the wrong authority.
	if m.PolicyDecisionPoint != strings.TrimSuffix(pdp, "/") && m.PolicyDecisionPoint != pdp {
		return Metadata{}, fmt.Errorf(
			"authzen: metadata at %s declares PDP %q, expected %q",
			wellKnown.String(), m.PolicyDecisionPoint, pdp)
	}
	if m.AccessEvaluationEndpoint == "" {
		return Metadata{}, fmt.Errorf("authzen: metadata for %q declares no access_evaluation_endpoint", pdp)
	}

	return m, nil
}

// randomID generates the value for X-Request-ID.
//
// It returns an empty string if the system entropy source fails, which omits
// the header. Losing traceability on one request is preferable to failing the
// request, and the alternative — a predictable or repeated identifier — would
// let two decisions be confused for each other.
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
