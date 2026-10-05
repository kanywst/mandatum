# Interoperability

The v0.2 gate in [ROADMAP.md](../../ROADMAP.md) is that the enforcement point works against three Policy Decision Points from different projects with no implementation-specific code paths. This directory is how that is checked, and what checking it found.

Last run against the versions below: 2026-10-05.

## What runs

[`interop_test.go`](interop_test.go) runs one scenario through `pkg/mcp.Enforcer` with the stock `authzen.Client`, against every PDP it is given. A real chain is issued and verified, so every request a PDP sees is the one a deployment would send. Nothing in the test knows which PDP it is talking to. What differs is each PDP's policy, written in its own language and saying the same thing:

> Allow only the sponsor `u-8f31c02e`, authenticated at `https://idp.example.org`, acting through the agent `spiffe://example.org/ns/agents/retriever`, to call `search.query` (the default `tools/call` mapping) or to `query` the `public` index (a declared mapping). Deny everything else.

Every case but the first two allowed ones differs from an allowed one in exactly one field the PDP has to read. A PDP that ignores that field allows the case, and the test fails. A deny passes only if the PDP itself denied. A PDP that could not be reached, or that answered something the client could not read, also refuses the call, but the test fails it, because that refusal proves nothing about interoperability.

| Case | Field the PDP must read |
| --- | --- |
| `search.query` by the sponsor through the agent | allowed |
| `search.fetch` | `resource.id` |
| a different sponsor | `subject.id` |
| a different agent | `context.agent` |
| declared mapping, `public` index | allowed |
| declared mapping, `private` index | `resource.id`, from a mapping expression |

The chain grants every `search.*` tool, so the chain's own grant never decides a case. Every refusal here is the PDP's.

[`run.sh`](run.sh) starts the PDPs on loopback, loads the policies, and runs the test. The [`interop`](../../.github/workflows/interop.yml) workflow downloads pinned releases, checks their digests and calls the script, on every pull request that touches the client, the enforcement point, or this directory.

## The PDPs

| PDP | Version | Policy | All six cases |
| --- | --- | --- | --- |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) through the [contrib AuthZEN proxy](https://github.com/open-policy-agent/contrib/tree/main/authzen/authzen-proxy) | OPA 1.21.1, contrib `5b21e4c` | [`opa/policy.rego`](opa/policy.rego) | yes |
| [Cerbos](https://github.com/cerbos/cerbos) | 0.56.0 | [`cerbos/`](cerbos) | five; the `context.agent` case cannot be written |
| [OpenFGA](https://github.com/openfga/openfga), `--experimentals=authzen` | 1.21.0 | [`openfga/`](openfga) | yes |

All three are on the AuthZEN working group's interop list, and none of them shares code with this project. kanywst/opa-authzen-plugin is excluded, because it has the same author.

## What it found

The client needs no PDP-specific code. That is the gate. The run also found two things about the PDPs that a deployment has to know, and both are recorded here rather than worked around.

**Two of the three do not echo `X-Request-ID`.** The Authorization API says a PDP that receives a request identifier MUST return it. `authzen.Client` sends one, and refuses an answer that comes back without it or with a different one, because an answer it cannot tie to its question may belong to another question.

- Cerbos returns no `X-Request-ID`.
- OpenFGA returns its own identifier in place of the one it was sent.
- Only the OPA proxy echoes it.

With the default client, neither Cerbos nor OpenFGA gets a single answer accepted. Both work with `authzen.WithRequestID(func() string { return "" })`, which sends no identifier and so checks none. That is configuration every deployment already has, not a code path. But it gives up correlation between the PEP's log and the PDP's, and a deployment choosing it should know that is what it has done.

**Cerbos policies cannot read the request context.** Cerbos maps `subject` and `resource`, their properties included, onto its principal and resource, and reads `context` only for its own `cerbos.*` keys. So no Cerbos policy can condition on `context.agent`, or on anything in `context["mandatum.delegation"]`: which agent is acting, who was upstream, the chain's depth. Behind Cerbos, a policy can decide by sponsor and by tool, but not by agent. That gap matters for this project in particular, and it is why the `context.agent` case is reported as skipped for Cerbos rather than passed. A declared mapping can project the agent into `subject.properties` or `resource.properties`, where Cerbos can see it; the default mapping does not.

Two smaller ones, not needed by this scenario:

- OpenFGA serves the evaluation endpoint under a store path (`/stores/{id}/access/v1/evaluation`). Its metadata document reports a PDP identifier that discovery cannot round-trip, so `authzen.Discover` does not work against it, and the endpoint is configured directly.
- The OPA proxy answers its metadata path with 500 and has no `evaluations` endpoint. Neither is used here.

## Running it

With the binaries on disk and `npm ci` run in the proxy's directory:

```bash
CERBOS=/path/to/cerbos OPENFGA=/path/to/openfga OPA=/path/to/opa \
PROXY_DIR=/path/to/contrib/authzen/authzen-proxy \
  test/interop/run.sh
```

To add a PDP, write the policy above in its language. Then add one entry to `MANDATUM_INTEROP_PDPS` in `run.sh`, and a flag only where the PDP falls short of the specification in one of the two ways above.
