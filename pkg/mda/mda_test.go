package mda

import (
	"encoding/json"
	"strings"
	"testing"
)

// valid returns a structurally well-formed depth-1 assertion. Tests mutate a
// copy of it so that each negative case differs from a passing case in exactly
// one respect, which is what makes a failure informative.
func valid() Claims {
	return Claims{
		Issuer:    "spiffe://example.org/ns/agents/planner",
		Subject:   "spiffe://example.org/ns/agents/retriever",
		Audience:  "https://mcp.example.org",
		IssuedAt:  1789200000,
		ExpiresAt: 1789203600,
		ID:        "01JB2X9K7P4Q8R3N6M0V5T2Y7C",
		Mandatum: Mandatum{
			Version:  Version,
			Root:     Sponsor{Issuer: "https://idp.example.org", Subject: "u-8f31c02e"},
			Parent:   "sha-256:9f2bc41a",
			Depth:    1,
			MaxDepth: 3,
			Capabilities: []Capability{{
				Resource: ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:   ActionPattern{Name: "invoke"},
			}},
		},
	}
}

func TestValidateAcceptsWellFormed(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("well-formed assertion rejected: %v", err)
	}
}

// A verifier that accepts everything passes every positive test, so the
// negative cases below are the ones that carry weight. Each maps to a
// structural rule in docs/spec/delegation-assertion.md.
func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Claims)
		wantSub string
	}{
		{"unsupported version", func(c *Claims) { c.Mandatum.Version = 2 }, "unsupported version"},
		{"missing issuer", func(c *Claims) { c.Issuer = "" }, "iss is required"},
		{"missing subject", func(c *Claims) { c.Subject = "" }, "sub is required"},
		{"missing jti", func(c *Claims) { c.ID = "" }, "jti is required"},
		{"no expiry", func(c *Claims) { c.ExpiresAt = 0 }, "exp is required"},
		{"no sponsor issuer", func(c *Claims) { c.Mandatum.Root.Issuer = "" }, "must identify a sponsor"},
		{"no sponsor subject", func(c *Claims) { c.Mandatum.Root.Subject = "" }, "must identify a sponsor"},
		{"negative depth", func(c *Claims) { c.Mandatum.Depth = -1 }, "must not be negative"},
		{
			"root commits to a parent",
			func(c *Claims) { c.Mandatum.Depth = 0 },
			"depth 0 must not commit to a parent",
		},
		{
			"non-root without a parent",
			func(c *Claims) { c.Mandatum.Parent = "" },
			"must commit to a parent",
		},
		{
			"max_depth leaves no room",
			func(c *Claims) { c.Mandatum.MaxDepth = 1 },
			"leaves no room",
		},
		{
			"absent capabilities",
			func(c *Claims) { c.Mandatum.Capabilities = nil },
			"mdt.cap is required",
		},
		{
			"capability without resource type",
			func(c *Claims) { c.Mandatum.Capabilities[0].Resource.Type = "" },
			"resource.type is required",
		},
		{
			"capability without action",
			func(c *Claims) { c.Mandatum.Capabilities[0].Action.Name = "" },
			"action.name is required",
		},
		{
			"sequence that constrains nothing",
			func(c *Claims) { c.Mandatum.Sequence = &Sequence{} },
			"constrains nothing",
		},
		{
			"constraint without an id",
			func(c *Claims) {
				c.Mandatum.Sequence = &Sequence{Constraints: []Constraint{{
					Forbid: ActionMatcher{ResourceTags: []string{"mutating"}},
					After:  ActionMatcher{ResourceTags: []string{"external-content"}},
				}}}
			},
			"has no id",
		},
		{
			"condition with no comparison",
			func(c *Claims) {
				c.Mandatum.Capabilities[0].Conditions = map[string]Condition{"args.index": {}}
			},
			"restricts nothing",
		},
		{
			"condition with two comparisons",
			func(c *Claims) {
				eq := "public"
				c.Mandatum.Capabilities[0].Conditions = map[string]Condition{
					"args.index": {Equals: &eq, In: []string{"docs"}},
				}
			},
			"exactly one is permitted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("accepted an assertion that should be rejected: %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not mention %q", err, tt.wantSub)
			}
		})
	}
}

// An empty capability list is valid and grants nothing. It must not be
// confused with an absent one, which is invalid: the difference is between
// "this delegation grants no authority" and "the issuer forgot to say".
func TestEmptyCapabilitiesGrantNothingAndAreValid(t *testing.T) {
	c := valid()
	c.Mandatum.Capabilities = []Capability{}
	if err := c.Validate(); err != nil {
		t.Fatalf("empty capability list rejected: %v", err)
	}
}

func TestDigestIsStableAndDistinguishing(t *testing.T) {
	a := Digest([]byte("eyJhbGciOiJFZERTQSJ9.payload.signature"))
	again := Digest([]byte("eyJhbGciOiJFZERTQSJ9.payload.signature"))
	other := Digest([]byte("eyJhbGciOiJFZERTQSJ9.payload.signaturf"))

	if a != again {
		t.Errorf("digest is not deterministic: %q then %q", a, again)
	}
	if a == other {
		t.Error("digest does not distinguish a one-byte difference")
	}
	if !strings.HasPrefix(a, "sha-256:") {
		t.Errorf("digest %q lacks the algorithm prefix", a)
	}
}

// The Parent commitment is taken over bytes as received. This test pins that
// behaviour: if someone changes Digest to hash re-encoded claims, two distinct
// wire forms could collide and chain splicing would become possible.
func TestDigestCoversSerializationNotSemantics(t *testing.T) {
	one := []byte(`{"a":1,"b":2}`)
	two := []byte(`{"b":2,"a":1}`)

	var x, y map[string]int
	if err := json.Unmarshal(one, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(two, &y); err != nil {
		t.Fatal(err)
	}
	if len(x) != len(y) {
		t.Fatal("test inputs are not semantically equal")
	}

	if Digest(one) == Digest(two) {
		t.Error("semantically equal but textually different inputs share a digest; " +
			"Digest must commit to the serialization")
	}
}

func FuzzClaimsValidate(f *testing.F) {
	seed, err := json.Marshal(valid())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"mdt":{"v":1}}`))

	// Validate must terminate and must never panic, whatever it is handed.
	// Parsing untrusted assertions is the first thing a verifier does, so a
	// panic here is a denial of service on the enforcement path.
	f.Fuzz(func(t *testing.T, data []byte) {
		var c Claims
		if err := json.Unmarshal(data, &c); err != nil {
			return
		}
		_ = c.Validate()
	})
}
