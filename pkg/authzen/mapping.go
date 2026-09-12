package authzen

import (
	"github.com/kanywst/mandatum/pkg/verify"
)

// DelegationContextKey is the request-context attribute carrying the verified
// delegation chain.
//
// The COAZ-MCP binding places the human in `subject` and the acting client in
// `context.agent`, and states that upstream actors are separately addressable
// and out of scope for that field. It does not say where they go or what a PEP
// must verify about them. This is Mandatum's answer to that gap, under a
// vendor-prefixed key so that it cannot be mistaken for something the binding
// defines.
//
// Its presence is itself a claim: a PEP populates it only from a chain that
// passed every rule in the specification. A PDP that finds it may rely on it
// for the same reason it may rely on `subject.id` — the PEP checked it.
const DelegationContextKey = "mandatum.delegation"

// AgentContextKey is `context.agent` from the COAZ-MCP binding: the acting
// client, one hop, never a chain.
const AgentContextKey = "agent"

// SubjectType is the COAZ-MCP subject type. The subject is the principal on
// whose behalf access is requested — under Mandatum, the human sponsor.
const SubjectType = "identity"

// ToolResourceType is the COAZ-MCP resource type for a tool call.
const ToolResourceType = "tool"

// ToolCallAction is the COAZ-MCP action name for `tools/call`.
const ToolCallAction = "tools/call"

// ToolCall is the MCP request being authorized.
type ToolCall struct {
	// Name is the tool, from the JSON-RPC params. It becomes resource.id.
	Name string
	// Arguments are the caller-supplied values. They are attached to the
	// resource so that policy can condition on them, which is the whole
	// point of authorizing at the tool call rather than at the connection.
	Arguments map[string]any
	// Server identifies the MCP server, for policy that varies by deployment.
	Server string
}

// Delegation is the verified chain as a PDP sees it.
type Delegation struct {
	// Sponsor is the human at the root, repeated from subject.id so that a
	// policy reading only this object still has the attribution.
	Sponsor SponsorRef `json:"sponsor"`
	// Chain is the digest of the exact verified chain. Two chains with the
	// same actors but different links have different digests, which is what
	// separates this from an unverified list.
	Chain string `json:"chain"`
	// Actors runs from the agent the sponsor granted to, down to the acting
	// agent. This is the "who was upstream" answer.
	Actors []string `json:"actors"`
	// Depth is the number of delegation hops below the sponsor.
	Depth int `json:"depth"`
	// Leaf is the acting assertion's identifier: the handle to revoke this
	// agent, and nothing else.
	Leaf string `json:"leaf"`
}

// SponsorRef identifies the human a chain is rooted in.
type SponsorRef struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	// Methods is how the sponsor authenticated, so a policy can require
	// step-up before a high-impact delegation is honoured.
	Methods []string `json:"amr,omitempty"`
	// AuthenticatedAt lets a policy require a recent authentication rather
	// than a session that started last month.
	AuthenticatedAt int64 `json:"auth_time,omitempty"`
}

// ToolCallRequest maps a verified chain and an MCP tool call onto an Access
// Evaluation request, following the COAZ-MCP default mapping for `tools/call`.
//
// The mapping is deliberately unsurprising:
//
//   - subject is the human sponsor, per COAZ-MCP's subject-identity claim;
//   - context.agent is the acting agent, one hop, as the binding requires;
//   - the rest of the chain goes in context under a prefixed key, because the
//     binding leaves upstream actors undefined rather than forbidding them.
//
// The result carries no field a PDP must trust on the PEP's word beyond what
// verification established. Pass only a Result that verify.Verify returned
// without error; there is no way for this function to check that for you,
// which is why it takes the result type rather than a raw chain.
func ToolCallRequest(res *verify.Result, call ToolCall) Request {
	resourceProps := map[string]any{}
	if call.Server != "" {
		resourceProps["server"] = call.Server
	}
	if len(call.Arguments) > 0 {
		resourceProps["arguments"] = call.Arguments
	}
	if len(resourceProps) == 0 {
		resourceProps = nil
	}

	return Request{
		Subject: Subject{
			Type: SubjectType,
			ID:   res.Sponsor.Subject,
			Properties: map[string]any{
				// The sponsor's identifier is only unique within its issuer,
				// so the issuer travels with it. Without this, two sponsors
				// from different identity providers can collide.
				"iss": res.Sponsor.Issuer,
			},
		},
		Action:   Action{Name: ToolCallAction},
		Resource: Resource{Type: ToolResourceType, ID: call.Name, Properties: resourceProps},
		Context: map[string]any{
			AgentContextKey:      res.Agent,
			DelegationContextKey: delegationOf(res),
		},
	}
}

func delegationOf(res *verify.Result) Delegation {
	return Delegation{
		Sponsor: SponsorRef{
			Issuer:          res.Sponsor.Issuer,
			Subject:         res.Sponsor.Subject,
			Methods:         res.Sponsor.AuthenticationMethods,
			AuthenticatedAt: res.Sponsor.AuthenticatedAt,
		},
		Chain:  res.ChainDigest,
		Actors: res.Actors,
		Depth:  res.Depth,
		Leaf:   res.LeafID,
	}
}
