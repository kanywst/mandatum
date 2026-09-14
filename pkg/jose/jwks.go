package jose

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Specification section 7 rule V3 says a key is resolved for an assertion's
// issuer "through the SPIFFE trust bundle or the issuer's JWKS". KeyRing does
// not do that: it holds whatever a caller put in it. This is the other half —
// the same verification path, with the keys fetched from a document the
// issuer publishes.
//
// The two are interchangeable at the SignatureVerifier interface, and a
// deployment that pins keys by hand should keep using KeyRing. This exists
// for the deployment that cannot: an issuer rotating on its own schedule,
// or a SPIFFE trust domain whose bundle is the authority on its own keys.

// defaults for a JWKS resolver, chosen so that the zero-configuration case is
// the safe one.
const (
	defaultJWKSTTL     = 5 * time.Minute
	defaultJWKSTimeout = 5 * time.Second
	// A key document is a few kilobytes. The cap is three orders of magnitude
	// above that, and exists so that a compromised or hostile endpoint cannot
	// make a verifier read forever.
	defaultJWKSMaxBytes = 1 << 20
	// An unknown `kid` is the signal that an issuer rotated, and the reason to
	// refetch before failing. It is also free for an attacker to produce, so
	// refetching is rate-limited per issuer.
	defaultJWKSMinRefresh = 30 * time.Second
)

// JWKS resolves verification keys by fetching each issuer's key document, and
// implements the SignatureVerifier interface the chain verifier depends on.
//
// Which document belongs to which issuer is configuration, set by AddSource.
// It is never read from the assertion, and never discovered by dereferencing
// the issuer identifier: an assertion that could name where its own key comes
// from is an assertion that verifies against a key its holder generated.
//
// The zero value is not usable; call NewJWKS.
type JWKS struct {
	sources map[string]string
	client  *http.Client
	ttl     time.Duration
	// minRefresh bounds how often an unknown kid can force a fetch.
	minRefresh time.Duration
	maxBytes   int64
	now        func() time.Time

	mu    sync.Mutex
	cache map[string]*keySet
}

type keySet struct {
	// keys is keyed the same way KeyRing keys are: kid, with "" meaning the
	// document published exactly one usable key and an assertion may omit
	// `kid`.
	keys       map[string]ed25519.PublicKey
	fetchedAt  time.Time
	lastTried  time.Time
	sequence   uint64
	fetchedURL string
}

// JWKSOption configures a JWKS resolver.
type JWKSOption func(*JWKS)

// WithHTTPClient replaces the client used to fetch key documents. Use it to
// supply a client with the trust roots, proxy, or transport a deployment
// requires; the default client has a five second timeout and nothing else.
func WithHTTPClient(c *http.Client) JWKSOption {
	return func(j *JWKS) {
		if c != nil {
			j.client = c
		}
	}
}

// WithCacheTTL sets how long a fetched key document is trusted before it is
// fetched again. A shorter window shortens the time a revoked signing key
// remains usable; a longer one survives a longer outage of the key endpoint.
func WithCacheTTL(d time.Duration) JWKSOption {
	return func(j *JWKS) {
		if d > 0 {
			j.ttl = d
		}
	}
}

// WithClock replaces the clock, for tests.
func WithClock(now func() time.Time) JWKSOption {
	return func(j *JWKS) {
		if now != nil {
			j.now = now
		}
	}
}

// NewJWKS returns a resolver with no sources. Add one per issuer whose keys
// should be fetched.
func NewJWKS(opts ...JWKSOption) *JWKS {
	j := &JWKS{
		sources:    map[string]string{},
		client:     &http.Client{Timeout: defaultJWKSTimeout},
		ttl:        defaultJWKSTTL,
		minRefresh: defaultJWKSMinRefresh,
		maxBytes:   defaultJWKSMaxBytes,
		now:        time.Now,
		cache:      map[string]*keySet{},
	}
	for _, o := range opts {
		o(j)
	}
	return j
}

// AddSource registers the URL publishing an issuer's verification keys. The
// document may be a plain JWKS or a SPIFFE trust domain bundle, which is a
// JWKS carrying additional members.
//
// The URL must be https. A key document fetched over plaintext is a forged
// chain waiting for a network position, and no amount of care further down
// recovers from that.
func (j *JWKS) AddSource(issuer, jwksURL string) error {
	if issuer == "" {
		return errors.New("jose: issuer is required")
	}
	u, err := url.Parse(jwksURL)
	if err != nil {
		return fmt.Errorf("jose: key source for %q: %w", issuer, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("jose: key source for %q must be https, got %q", issuer, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("jose: key source for %q has no host", issuer)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.sources[issuer] = u.String()
	delete(j.cache, issuer)
	return nil
}

// VerifySignature checks that issuer signed compact, resolving the key from
// the document registered for that issuer.
//
// A key that cannot be resolved is an error, not an allow. That means an
// outage of a key endpoint denies rather than admits, which is the direction
// this project errs in everywhere: refusing a valid chain is recoverable and
// accepting an invalid one is not.
func (j *JWKS) VerifySignature(ctx context.Context, issuer string, compact []byte) error {
	h, _, err := Parse(compact)
	if err != nil {
		return err
	}

	key, err := j.key(ctx, issuer, h.KeyID)
	if err != nil {
		return err
	}

	parts := strings.Split(string(compact), ".")
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("jose: decoding signature: %w", err)
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("jose: signature does not verify")
	}
	return nil
}

// key returns the verification key for an issuer and kid, fetching or
// refreshing the issuer's document when it has to.
func (j *JWKS) key(ctx context.Context, issuer, kid string) (ed25519.PublicKey, error) {
	j.mu.Lock()
	src, ok := j.sources[issuer]
	if !ok {
		j.mu.Unlock()
		return nil, fmt.Errorf("%w: no key source registered for issuer %q", ErrUnknownKey, issuer)
	}
	set := j.cache[issuer]
	now := j.now()

	fresh := set != nil && now.Sub(set.fetchedAt) < j.ttl
	if fresh {
		if k, found := set.keys[kid]; found {
			j.mu.Unlock()
			return k, nil
		}
		// An unknown kid under a fresh document means either a rotation this
		// verifier has not seen, or an attacker naming a key that does not
		// exist. Refetch for the first, rate-limited because of the second.
		if now.Sub(set.lastTried) < j.minRefresh {
			j.mu.Unlock()
			return nil, fmt.Errorf("%w: issuer %q, kid %q", ErrUnknownKey, issuer, kid)
		}
	}
	if set != nil {
		set.lastTried = now
	}
	j.mu.Unlock()

	fetched, err := j.fetch(ctx, issuer, src)
	if err != nil {
		return nil, err
	}

	j.mu.Lock()
	// A bundle carrying a sequence number that has gone backwards is a replay
	// of an older document, which is how a revoked key gets reinstated.
	if set != nil && fetched.sequence != 0 && set.sequence > fetched.sequence {
		j.mu.Unlock()
		return nil, fmt.Errorf("jose: key document for %q went backwards (sequence %d after %d)",
			issuer, fetched.sequence, set.sequence)
	}
	fetched.lastTried = j.now()
	j.cache[issuer] = fetched
	k, found := fetched.keys[kid]
	j.mu.Unlock()

	if !found {
		return nil, fmt.Errorf("%w: issuer %q, kid %q", ErrUnknownKey, issuer, kid)
	}
	return k, nil
}

// jwk is the subset of a JSON Web Key this package can use. Everything else
// in a document is ignored rather than rejected: a SPIFFE bundle legitimately
// carries keys for other purposes, and a JWKS may carry algorithms this
// verifier does not accept. What matters is that no such key can be selected.
type jwk struct {
	KeyType   string   `json:"kty"`
	Curve     string   `json:"crv"`
	X         string   `json:"x"`
	KeyID     string   `json:"kid"`
	Use       string   `json:"use"`
	Algorithm string   `json:"alg"`
	KeyOps    []string `json:"key_ops"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
	// SPIFFE trust domain bundles carry a monotonic sequence number. It is
	// read so that an older bundle cannot replace a newer one.
	SPIFFESequence uint64 `json:"spiffe_sequence"`
}

func (j *JWKS) fetch(ctx context.Context, issuer, src string) (*keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, fmt.Errorf("jose: key document for %q: %w", issuer, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jose: fetching keys for %q: %w", issuer, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jose: fetching keys for %q: HTTP %d", issuer, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, j.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jose: reading keys for %q: %w", issuer, err)
	}
	if int64(len(body)) > j.maxBytes {
		return nil, fmt.Errorf("jose: key document for %q is larger than %d bytes", issuer, j.maxBytes)
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jose: parsing keys for %q: %w", issuer, err)
	}

	set := &keySet{
		keys:       map[string]ed25519.PublicKey{},
		fetchedAt:  j.now(),
		sequence:   doc.SPIFFESequence,
		fetchedURL: src,
	}
	// Unusable keys are skipped rather than counted, so a bundle carrying an
	// RSA key for something else does not change how the Ed25519 ones are
	// treated.
	type identified struct {
		kid string
		key ed25519.PublicKey
	}
	var usable []identified
	for _, k := range doc.Keys {
		if key, ok := k.ed25519Key(); ok {
			usable = append(usable, identified{kid: k.KeyID, key: key})
		}
	}
	if len(usable) == 0 {
		return nil, fmt.Errorf("jose: key document for %q has no Ed25519 keys this verifier can use", issuer)
	}
	for _, u := range usable {
		if u.kid == "" && len(usable) > 1 {
			// A key without a kid among several cannot be selected
			// unambiguously, and guessing is how the wrong key gets used.
			return nil, fmt.Errorf("jose: key document for %q has an unidentified key among %d", issuer, len(usable))
		}
		if existing, clash := set.keys[u.kid]; clash && !existing.Equal(u.key) {
			return nil, fmt.Errorf("jose: key document for %q has two different keys with kid %q", issuer, u.kid)
		}
		set.keys[u.kid] = u.key
	}
	// An assertion from a single-key issuer may legitimately omit `kid`. With
	// more than one it must say which, because picking for it is picking
	// wrong eventually.
	if len(usable) == 1 {
		set.keys[""] = usable[0].key
	}
	return set, nil
}

// ed25519Key reports the key as an Ed25519 public key, or false if it is not
// one this verifier may use.
func (k jwk) ed25519Key() (ed25519.PublicKey, bool) {
	if k.KeyType != "OKP" || k.Curve != "Ed25519" {
		return nil, false
	}
	// `alg`, `use` and `key_ops` are advisory, but where present they must not
	// contradict what the key is about to be used for. A key published for
	// encryption is not a key for verifying an assertion.
	if k.Algorithm != "" && k.Algorithm != Algorithm {
		return nil, false
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, false
	}
	if len(k.KeyOps) > 0 {
		permitted := false
		for _, op := range k.KeyOps {
			if op == "verify" {
				permitted = true
				break
			}
		}
		if !permitted {
			return nil, false
		}
	}
	raw, err := b64.DecodeString(k.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}
