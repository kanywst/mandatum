# COAZ-MCP conformance

Last checked against the AuthZEN COAZ-MCP Binding 1.0 Working Group Draft (June 2026): 2026-09-13. That date is when the mapping was last read against the draft, which is the claim worth dating; it is not when this file was last edited, and `git log` has that.

[The specification](delegation-assertion.md) §8 says Mandatum follows the COAZ-MCP binding rather than defining a parallel mapping. This is where that claim is made checkable: what is implemented, what is not, and the one place the output goes beyond what the binding defines.

The binding is a working group draft and will move. Anything here can become wrong without this project changing, which is why the date at the top matters.

## What is implemented

`authzen.ToolCallRequest` produces the binding's default mapping for `tools/call`. The authority for what it emits is the test named at the foot of this document, which asserts each field; the table renders that test in prose, and the worked JSON in [the specification](delegation-assertion.md) §8 renders it as an example. If the three ever disagree, the test is right and the other two are stale.

| Binding | Mandatum |
| --- | --- |
| `subject.type` | `identity` |
| `subject.id`, from the subject-identity claim | the chain's sponsor, the human at the root |
| `context.agent`, from `$token.?client_id` | the leaf agent: the principal actually acting |
| `action.name` | `tools/call` |
| `resource.type` | `tool` |
| `resource.id`, from `$params.name` | the tool name |

The subject-identity claim deserves a note. The binding says `subject.id` is conventionally `$token.sub`, and that a deployment issuing tokens with the agent as principal MAY designate an on-behalf-of claim instead so that `subject.id` carries the human. A Mandatum chain has the human at its root by construction, so the sponsor is used directly and no claim designation is needed. A deployment that also uses OAuth for the same call should make sure the two agree on who the subject is.

Arguments and the server identifier go in `resource.properties`. The binding does not define them there. Its default `tools/call` mapping is a fixed object with no `properties` on either subject or resource, and the place it provides for projecting `$params.arguments` is a declared mapping, which this project does not implement. So these fields are ours, and §Divergences says so.

## What is not implemented

- **Only `tools/call`.** The binding gives default mappings for `tools/list`, `resources/list`, `resources/read`, `resources/subscribe`, `resources/unsubscribe`, `prompts/list`, `prompts/get`, `completion/complete`, `logging/setLevel`, and the four `tasks/*` methods as well. None of those are mapped.
- **Neither of the binding's two catch-all behaviours.** `ping` and `notifications/*` are pass-through: "the PEP MUST NOT call the PDP for them and MUST allow them to proceed". A method with neither a default nor a declared mapping "MUST be denied". Both are normative PEP requirements rather than mappings, and a PEP built on this library has to implement them itself, fail-closed included.

  `pkg/mcp.Enforcer.Middleware` is now such a PEP, and it does not implement them: it enforces `tools/call` and forwards every other method to the server behind it. That is deliberate and it is a divergence, not an oversight — a delegation chain says nothing about `tools/list`, and this middleware is a per-call layer above MCP's own transport authorization rather than a replacement for it. A deployment that needs the binding's deny-by-default over unmapped methods has to add it, and should not read "Mandatum follows the COAZ-MCP binding" as saying it is already there. Server-initiated requests need nothing: the binding puts them out of scope for this version.
- **No declared mappings.** The binding lets a tool declare an `x-authzen-mapping` in its `inputSchema`, with CEL expressions over `params` and `token`. Mandatum reads neither, so a tool that declares a mapping is authorized by the default mapping instead. This is a real gap for parameter-level policy, and it is the next thing to build here.
- **No CEL.** Follows from the above.
- **No Access Evaluations batching.** Single evaluation only; the binding's multi-evaluation examples are not supported.

## The one addition

`context` carries a vendor-prefixed `mandatum.delegation` object alongside `context.agent`.

What the binding says about `context.agent` is that it carries the agent identity, typically `$token.?client_id`, and that separating it from `subject` lets a policy judge the user and the agent independently. It defines no place for the hops in between. It does not say one exists, or that a chain does not belong in `context.agent`; it simply does not address the question, and this project should not put words in it. The prefixed key stays out of the binding's namespace so a future version cannot collide with it, and so a PDP reading only what the binding defines is unaffected.

Whether the binding should define a place for it is open, and being discussed in the `context.agent` trust-semantics thread, [openid/authzen#612](https://github.com/openid/authzen/issues/612). The editor has proposed there that `context.agent` "never carries a delegation chain" and that "upstream actors are separately addressable", which is the reading this document assumed before checking. That is a proposal in an open issue awaiting a chair's read, not binding text and not a resolution. If it lands, this object moves wherever the binding names, and this document records the move.

## Divergences

Both are ours rather than the binding's.

The `_meta` key a chain travels in, specification §8.1, is defined by this project. The binding maps an MCP request onto an evaluation request; it says nothing about how a delegation chain reaches the PEP, because it has no delegation chain. The key sits under a reverse-DNS prefix MCP's own rules mark as third-party, so nothing here occupies a name either specification might later want.

`resource.properties` and `subject.properties` in the emitted request are not part of the default `tools/call` mapping, which is a fixed object with neither. The binding's own mechanism for projecting arguments into a request is a declared mapping, and the section on omitted inputs is explicit that a decision covers only the request the selected mapping constructed. Sending more than the mapping defines does not break a PDP that ignores unknown members, but it is a wider request than the binding specifies, and a policy written against these fields would not port to a conforming PEP.

The mapping's six defined fields match field for field. That has not been checked against an interoperability suite, and the AuthZEN conformance program does not yet cover this binding. Until it does, the claim means the mapping was read from the draft and implemented field by field, with a test asserting each field, and nothing more.

## How to check

```bash
go test -run TestToolCallRequestFollowsTheCoazMapping ./pkg/authzen/ -v
```

This is the authoritative statement of the mapping. It asserts each field above, including the two that are easiest to get backwards: the human in `subject` and the acting agent in `context.agent`. A change to the mapping that does not break this test is a change nobody checked.
