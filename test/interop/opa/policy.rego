# The interop policy for Open Policy Agent, served through the AuthZEN proxy in
# open-policy-agent/contrib. The proxy hands OPA the evaluation request as
# input and returns this rule's value as the response body, so the rule has to
# produce exactly {"decision": bool}.
package authzen

import rego.v1

default allow["decision"] := false

allow["decision"] if {
	input.subject.type == "identity"
	input.subject.id == "u-8f31c02e"
	input.subject.properties.iss == "https://idp.example.org"
	input.context.agent == "spiffe://example.org/ns/agents/retriever"
	permitted
}

permitted if {
	input.action.name == "tools/call"
	input.resource.type == "tool"
	input.resource.id == "search.query"
}

permitted if {
	input.action.name == "query"
	input.resource.type == "index"
	input.resource.id == "public"
}
