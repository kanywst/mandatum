# COAZ-MCP conformance

Last updated: 2026-09-13. Against the AuthZEN COAZ-MCP Binding 1.0 Working Group Draft, June 2026.

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

Arguments and the server identifier go in `resource.properties`, which the binding permits and does not require.

## What is not implemented

- **Only `tools/call`.** The binding also gives default mappings for `tools/list`, resources, prompts, completion, logging, tasks, pass-through operations, unknown methods and server-initiated requests. None of those are mapped.
- **No declared mappings.** The binding lets a tool declare an `x-coaz-mapping` in its `inputSchema`, with CEL expressions over `params` and `token`. Mandatum reads neither, so a tool that declares a mapping is authorized by the default mapping instead. This is a real gap for parameter-level policy, and it is the next thing to build here.
- **No CEL.** Follows from the above.
- **No Access Evaluations batching.** Single evaluation only; the binding's multi-evaluation examples are not supported.

## The one addition

`context` carries a vendor-prefixed `mandatum.delegation` object alongside `context.agent`.

This is an addition, not a divergence. The binding states that `context.agent` names one acting client and never a chain, and that upstream actors are separately addressable — without saying where they go. The prefixed key stays out of the binding's namespace so a future version of the binding cannot collide with it, and so a PDP reading only what the binding defines is unaffected.

Whether the binding should define a place for it is open. The discussion is the `context.agent` trust-semantics thread, [openid/authzen#612](https://github.com/openid/authzen/issues/612) — the same issue is cited elsewhere in this repository for a separate, settled point about RFC 8693 §4.1, so the part that matters here is the resolution that upstream actors are "separately addressable" without saying where. If the binding names a place, this object moves there and this document records the move.

## Divergences

None known.

That is a claim about the default `tools/call` mapping, which is the only part implemented. It has not been checked against an interoperability suite, and the AuthZEN conformance program does not yet cover this binding. Until it does, "none known" means the mapping was read from the draft and implemented field by field, with a test asserting each field, and nothing more.

## How to check

```bash
go test -run TestToolCallRequestFollowsTheCoazMapping ./pkg/authzen/ -v
```

This is the authoritative statement of the mapping. It asserts each field above, including the two that are easiest to get backwards: the human in `subject` and the acting agent in `context.agent`. A change to the mapping that does not break this test is a change nobody checked.
