package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"

	"github.com/kanywst/mandatum/pkg/verify"
)

// MappingKey is where a tool declares its mapping under the COAZ-MCP
// binding: a member of the tool's `inputSchema` in the `tools/list` response.
const MappingKey = "x-authzen-mapping"

// MaxExpressionCost bounds the work one expression may do, in CEL's own cost
// units.
//
// A declared mapping is written by the MCP server, which is the party whose
// operation is being authorized. Its expressions are therefore untrusted code
// running on the enforcement point, on the path of every call to the tool,
// and an expression that never finishes is an enforcement point that never
// answers. The bound is far above anything the binding's examples need.
const MaxExpressionCost = 100_000

// MaxResolvedValues and MaxResolvedBytes bound what the expressions in one
// mapping may produce for one call, across every request it resolves to.
//
// The cost limit does not do this. CEL charges for referencing a variable,
// not for its size, so `params.arguments.k.map(x, params.arguments.l)` is
// cheap to evaluate and produces len(k) copies of l once it is turned into
// JSON — gigabytes, from a request body well under a megabyte. The cost
// limit bounds the work of evaluating; these bound the result.
const (
	MaxResolvedValues = 10_000
	MaxResolvedBytes  = 1 << 20
)

// MappingError is a declared mapping that could not produce a request: it is
// malformed, an expression failed, or what it produced contradicts what
// verification established. The binding calls this a mapping error, and a
// mapping error refuses the call.
type MappingError struct {
	Err error
}

func (e *MappingError) Error() string { return "authzen: mapping error: " + e.Err.Error() }

// Unwrap exposes the underlying error.
func (e *MappingError) Unwrap() error { return e.Err }

func mappingErr(format string, args ...any) error {
	return &MappingError{Err: fmt.Errorf(format, args...)}
}

// Mapping is a declared mapping: the `x-authzen-mapping` a tool carries in
// its input schema, which replaces the default `tools/call` mapping for that
// tool only.
//
// It is parsed and every expression compiled once, by ParseMapping, so that
// a mapping that cannot work is found when the deployment loads it rather
// than on the first call. A Mapping is safe for concurrent use.
type Mapping struct {
	top     object
	entries []object // nil under the `evaluation` envelope
}

// ParseMapping reads a mapping: a JSON object with exactly one member,
// `evaluation` or `evaluations`, whose value is a request template.
//
// The template is checked more strictly than the binding requires. A member
// the Access Evaluation API does not define is refused rather than carried,
// because a PEP that forwards what it does not understand is vouching for it;
// and `options` is refused under `evaluations`, because the one thing it can
// choose — the evaluation semantic — is the thing the binding fixes as "allow
// only if every decision permits".
func ParseMapping(raw []byte) (*Mapping, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Literals are used verbatim, and a number that round-trips through
	// float64 is not verbatim once it is past 2^53.
	dec.UseNumber()
	var envelope map[string]any
	if err := dec.Decode(&envelope); err != nil {
		return nil, mappingErr("the mapping is not a JSON object: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, mappingErr("the mapping has data after its closing brace")
	}
	if len(envelope) != 1 {
		return nil, mappingErr("a mapping has exactly one member, evaluation or evaluations; this one has %d", len(envelope))
	}

	var body any
	for key, v := range envelope {
		switch key {
		case "evaluation":
			top, err := compileTemplate(v, "evaluation", requestMembers)
			if err != nil {
				return nil, err
			}
			return &Mapping{top: top}, nil
		case "evaluations":
			body = v
		default:
			return nil, mappingErr("%q is not a mapping envelope; the binding defines evaluation and evaluations", key)
		}
	}

	fields, ok := body.(map[string]any)
	if !ok {
		return nil, mappingErr("evaluations is not an object")
	}
	if _, ok := fields["options"]; ok {
		return nil, mappingErr("evaluations sets options; the binding fixes the semantic as allow only if every decision permits")
	}
	list, ok := fields["evaluations"].([]any)
	if !ok || len(list) == 0 {
		return nil, mappingErr("evaluations.evaluations must be a non-empty array")
	}
	rest := make(map[string]any, len(fields)-1)
	for k, v := range fields {
		if k != "evaluations" {
			rest[k] = v
		}
	}
	top, err := compileTemplate(rest, "evaluations", requestMembers)
	if err != nil {
		return nil, err
	}

	m := &Mapping{top: top}
	for i, raw := range list {
		where := fmt.Sprintf("evaluations.evaluations[%d]", i)
		if entry, ok := raw.(map[string]any); ok {
			if _, smuggled := entry["subject"]; smuggled {
				// The binding's rule, and the reason for it: one subject
				// per request, anchored once, so no entry can evaluate as
				// somebody else.
				return nil, mappingErr("%s sets subject; under evaluations only the top-level subject is allowed", where)
			}
		}
		entry, err := compileTemplate(raw, where, entryMembers)
		if err != nil {
			return nil, err
		}
		m.entries = append(m.entries, entry)
	}
	return m, nil
}

// MappingFromInputSchema returns the mapping a tool's `inputSchema` declares,
// or nil if it declares none — in which case the default `tools/call`
// mapping applies. It is for a catalog built from a `tools/list` response.
func MappingFromInputSchema(inputSchema []byte) (*Mapping, error) {
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(inputSchema, &schema); err != nil {
		return nil, fmt.Errorf("authzen: reading inputSchema: %w", err)
	}
	raw, ok := schema[MappingKey]
	if !ok {
		return nil, nil
	}
	return ParseMapping(raw)
}

var (
	requestMembers = []string{"subject", "action", "resource", "context"}
	entryMembers   = []string{"action", "resource", "context"}
)

func compileTemplate(v any, where string, allowed []string) (object, error) {
	fields, ok := v.(map[string]any)
	if !ok {
		return nil, mappingErr("%s is not an object", where)
	}
	for key := range fields {
		if !contains(allowed, key) {
			return nil, mappingErr("%s has %q, which an evaluation request does not define", where, key)
		}
	}
	n, err := compile(fields, where)
	if err != nil {
		return nil, err
	}
	return n.(object), nil
}

// ToolCallRequests resolves the mapping for one verified call and returns the
// evaluation requests it constructs. The call is allowed only if every one of
// them is.
//
// Under `evaluations` this is the binding's fallback for a PDP without the
// Access Evaluations API — one request per entry, the top-level members
// applied as defaults exactly as the Authorization API defines them — used
// unconditionally, so that every PDP a Decider can reach is one this works
// against.
//
// Two inputs are exposed to expressions, as the binding names them:
//
//   - `params` is `{"name": ..., "arguments": ...}` from the call;
//   - `token` is what the chain established, shaped as the claims the
//     binding's expressions read: `sub` and `iss` are the sponsor, the
//     subject-identity claim, and `client_id` is the acting agent, with
//     `amr` and `auth_time` when the sponsor's grant carries them.
//
// `token` is not an OAuth access token, and nothing here reads one: every
// value in it was established by verification, which is the property the
// binding wants of a token and the reason it can stand in for one.
//
// Three values in the result are anchored to verification rather than taken
// from the mapping, because each one is an identity and the mapping is
// written by the server being authorized:
//
//   - `subject.id` is the sponsor. The binding lets a declared mapping
//     override it, with a warning, for deployments that cannot carry the
//     user in a token. A chain always carries the user, so here an override
//     is a mapping error instead;
//   - `subject.properties.iss` is the sponsor's issuer, which is what makes
//     `subject.id` unique;
//   - `context.agent` is the acting agent, and `context["mandatum.delegation"]`
//     is the verified chain, which a mapping may not write at all.
//
// A mapping that omits any of them has it supplied. A mapping that sets one
// to a different value is refused rather than corrected, since a mapping that
// names somebody else is not one to trust about anything else either.
func (m *Mapping) ToolCallRequests(ctx context.Context, res *verify.Result, call ToolCall) ([]Request, error) {
	vars := map[string]any{"params": paramsOf(call), "token": tokenOf(res)}
	b := newBudget(ctx)

	top, err := m.top.resolveObject(b, vars, "")
	if err != nil {
		return nil, err
	}
	if m.entries == nil {
		r, err := anchored(top, res)
		if err != nil {
			return nil, err
		}
		return []Request{r}, nil
	}

	requests := make([]Request, 0, len(m.entries))
	for i, entry := range m.entries {
		fields, err := entry.resolveObject(b, vars, fmt.Sprintf("evaluations[%d]", i))
		if err != nil {
			return nil, err
		}
		// A member an entry sets replaces the default whole. The
		// Authorization API defines defaults per key, not per field, so an
		// entry's context is its entire context rather than a patch.
		effective := make(map[string]any, len(top)+len(fields))
		for k, v := range top {
			effective[k] = v
		}
		for k, v := range fields {
			effective[k] = v
		}
		r, err := anchored(effective, res)
		if err != nil {
			var me *MappingError
			if errors.As(err, &me) {
				err = me.Err
			}
			return nil, mappingErr("evaluations[%d]: %w", i, err)
		}
		requests = append(requests, r)
	}
	return requests, nil
}

func paramsOf(call ToolCall) map[string]any {
	params := map[string]any{"name": call.Name}
	if call.Arguments != nil {
		params["arguments"] = call.Arguments
	}
	return params
}

func tokenOf(res *verify.Result) map[string]any {
	token := map[string]any{
		"iss":       res.Sponsor.Issuer,
		"sub":       res.Sponsor.Subject,
		"client_id": res.Agent,
	}
	if len(res.Sponsor.AuthenticationMethods) > 0 {
		amr := make([]any, len(res.Sponsor.AuthenticationMethods))
		for i, m := range res.Sponsor.AuthenticationMethods {
			amr[i] = m
		}
		token["amr"] = amr
	}
	if res.Sponsor.AuthenticatedAt != 0 {
		token["auth_time"] = res.Sponsor.AuthenticatedAt
	}
	return token
}

// anchored builds a request from resolved members and pins the identities in
// it to what verification established.
func anchored(fields map[string]any, res *verify.Result) (Request, error) {
	var r Request

	subject, err := optionalObject(fields, "subject")
	if err != nil {
		return r, err
	}
	if err := onlyMembers(subject, "subject", "type", "id", "properties"); err != nil {
		return r, err
	}
	r.Subject.Type = SubjectType
	if v, ok := subject["type"]; ok {
		if r.Subject.Type, err = nonEmptyString(v, "subject.type"); err != nil {
			return r, err
		}
	}
	r.Subject.ID = res.Sponsor.Subject
	if v, ok := subject["id"]; ok {
		id, err := nonEmptyString(v, "subject.id")
		if err != nil {
			return r, err
		}
		if id != res.Sponsor.Subject {
			return r, mappingErr("subject.id resolved to %s, which is not the chain's sponsor; a mapping cannot name the subject", brief(id))
		}
	}
	if r.Subject.Properties, err = optionalObject(subject, "properties"); err != nil {
		return r, err
	}
	if err := noFoldTwins(r.Subject.Properties, "subject.properties", "iss"); err != nil {
		return r, err
	}
	if v, ok := r.Subject.Properties["iss"]; ok && v != res.Sponsor.Issuer {
		return r, mappingErr("subject.properties.iss resolved to %s, which is not the sponsor's issuer", brief(v))
	}
	r.Subject.Properties = cloned(r.Subject.Properties)
	// Without the issuer, two sponsors with the same identifier at
	// different identity providers are one subject to the PDP.
	r.Subject.Properties["iss"] = res.Sponsor.Issuer

	action, err := requiredObject(fields, "action")
	if err != nil {
		return r, err
	}
	if err := onlyMembers(action, "action", "name", "properties"); err != nil {
		return r, err
	}
	if r.Action.Name, err = nonEmptyString(action["name"], "action.name"); err != nil {
		return r, err
	}
	if r.Action.Properties, err = optionalObject(action, "properties"); err != nil {
		return r, err
	}

	resource, err := requiredObject(fields, "resource")
	if err != nil {
		return r, err
	}
	if err := onlyMembers(resource, "resource", "type", "id", "properties"); err != nil {
		return r, err
	}
	if r.Resource.Type, err = nonEmptyString(resource["type"], "resource.type"); err != nil {
		return r, err
	}
	if r.Resource.ID, err = nonEmptyString(resource["id"], "resource.id"); err != nil {
		return r, err
	}
	if r.Resource.Properties, err = optionalObject(resource, "properties"); err != nil {
		return r, err
	}

	r.Context, err = optionalObject(fields, "context")
	if err != nil {
		return r, err
	}
	if err := noFoldTwins(r.Context, "context", AgentContextKey, DelegationContextKey); err != nil {
		return r, err
	}
	if v, ok := r.Context[AgentContextKey]; ok && v != res.Agent {
		return r, mappingErr("context.agent resolved to %s, which is not the acting agent", brief(v))
	}
	if _, ok := r.Context[DelegationContextKey]; ok {
		return r, mappingErr("context sets %q, which only the enforcement point may populate", DelegationContextKey)
	}
	r.Context = cloned(r.Context)
	r.Context[AgentContextKey] = res.Agent
	r.Context[DelegationContextKey] = delegationOf(res)

	return r, nil
}

// noFoldTwins refuses a key that is not one of the anchored keys but folds to
// one. Go's encoding/json matches object keys case-insensitively, with
// Unicode folding, and the last match wins; map keys are written sorted, and
// `iſſ` (with U+017F) sorts after `iss`. A PDP decoding into a struct would
// read the twin, and the anchored value would be on the wire for nothing.
func noFoldTwins(m map[string]any, what string, anchored ...string) error {
	for key := range m {
		for _, a := range anchored {
			if key != a && strings.EqualFold(key, a) {
				return mappingErr("%s has %q, which a case-insensitive decoder reads as %q", what, key, a)
			}
		}
	}
	return nil
}

// brief describes a resolved value for an error message without echoing it:
// a value can be as large as the budget allows, and it is the server's text
// on its way into an operator's log.
func brief(v any) string {
	if s, ok := v.(string); ok {
		const limit = 64
		if len(s) > limit {
			return fmt.Sprintf("%q…", truncate(s, limit))
		}
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("a %T", v)
}

// cloned copies a map before anchoring writes into it. Under `evaluations`
// the top-level members are shared by every entry, and writing the anchored
// values into the shared map would hand the next entry a context that already
// sets what only the enforcement point may set.
func cloned(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func requiredObject(fields map[string]any, key string) (map[string]any, error) {
	if _, ok := fields[key]; !ok {
		return nil, mappingErr("%s is required and the mapping does not produce it", key)
	}
	return optionalObject(fields, key)
}

func optionalObject(fields map[string]any, key string) (map[string]any, error) {
	v, ok := fields[key]
	if !ok {
		return nil, nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, mappingErr("%s resolved to %T, not an object", key, v)
	}
	return obj, nil
}

func onlyMembers(obj map[string]any, what string, allowed ...string) error {
	for key := range obj {
		if !contains(allowed, key) {
			return mappingErr("%s has %q, which the Authorization API does not define", what, key)
		}
	}
	return nil
}

func nonEmptyString(v any, what string) (string, error) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", mappingErr("%s must resolve to a non-empty string, not %s", what, brief(v))
	}
	return s, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// budget is what is left of the per-call bounds, and the call's context, so
// that converting a large result notices a cancelled call.
type budget struct {
	ctx    context.Context
	values int
	bytes  int
}

func newBudget(ctx context.Context) *budget {
	return &budget{ctx: ctx, values: MaxResolvedValues, bytes: MaxResolvedBytes}
}

func (b *budget) spend(bytes int) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	b.values--
	b.bytes -= bytes
	if b.values < 0 || b.bytes < 0 {
		return fmt.Errorf("the mapping produced more than %d values or %d bytes for one call", MaxResolvedValues, MaxResolvedBytes)
	}
	return nil
}

// The template is compiled into a tree of nodes, so that resolving it on a
// call evaluates programs rather than parsing source.
type node interface {
	// resolve returns the value, or present=false for an optional
	// expression whose key was missing.
	resolve(b *budget, vars map[string]any, path string) (v any, present bool, err error)
}

type (
	literal    struct{ v any }
	object     map[string]node
	array      []node
	expression struct {
		source string
		prog   cel.Program
	}
)

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func compile(v any, path string) (node, error) {
	switch v := v.(type) {
	case string:
		switch {
		case strings.HasPrefix(v, "$$"):
			return literal{v[1:]}, nil
		case strings.HasPrefix(v, "$"):
			return compileExpression(v[1:], path)
		default:
			return literal{v}, nil
		}
	case map[string]any:
		obj := make(object, len(v))
		for k, child := range v {
			n, err := compile(child, join(path, k))
			if err != nil {
				return nil, err
			}
			obj[k] = n
		}
		return obj, nil
	case []any:
		arr := make(array, len(v))
		for i, child := range v {
			n, err := compile(child, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			arr[i] = n
		}
		return arr, nil
	default:
		return literal{v}, nil
	}
}

var (
	celEnvOnce sync.Once
	celEnv     *cel.Env
	celEnvErr  error
)

// environment is the binding's: `params` and `token`, both maps, plus
// optional selection, which the binding requires for any value that may be
// absent. Cross-type numeric comparison is on because `params` comes from
// JSON, where every number is a double, and the binding's own example
// compares an argument against the integer literal 10000.
func environment() (*cel.Env, error) {
	celEnvOnce.Do(func() {
		celEnv, celEnvErr = cel.NewEnv(
			cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("token", cel.MapType(cel.StringType, cel.DynType)),
			cel.OptionalTypes(),
			cel.CrossTypeNumericComparisons(true),
		)
	})
	return celEnv, celEnvErr
}

func compileExpression(source, path string) (node, error) {
	env, err := environment()
	if err != nil {
		return nil, fmt.Errorf("authzen: building the CEL environment: %w", err)
	}
	ast, issues := env.Compile(source)
	if issues != nil && issues.Err() != nil {
		return nil, mappingErr("%s: expression %q does not compile: %w", path, "$"+source, issues.Err())
	}
	prog, err := env.Program(ast,
		cel.CostLimit(MaxExpressionCost),
		// Without this, ContextEval does not notice a cancelled context.
		cel.InterruptCheckFrequency(100),
	)
	if err != nil {
		return nil, mappingErr("%s: expression %q: %w", path, "$"+source, err)
	}
	return expression{source: "$" + source, prog: prog}, nil
}

func (l literal) resolve(*budget, map[string]any, string) (any, bool, error) {
	return l.v, true, nil
}

func (e expression) resolve(b *budget, vars map[string]any, path string) (any, bool, error) {
	out, _, err := e.prog.ContextEval(b.ctx, vars)
	if err != nil {
		return nil, false, mappingErr("%s: expression %q failed: %w", path, e.source, err)
	}
	v, present, err := jsonValue(out, b)
	if err != nil {
		return nil, false, mappingErr("%s: expression %q: %w", path, e.source, err)
	}
	return v, present, nil
}

func (o object) resolve(b *budget, vars map[string]any, path string) (any, bool, error) {
	v, err := o.resolveObject(b, vars, path)
	return v, err == nil, err
}

func (o object) resolveObject(b *budget, vars map[string]any, path string) (map[string]any, error) {
	out := make(map[string]any, len(o))
	for k, child := range o {
		v, present, err := child.resolve(b, vars, join(path, k))
		if err != nil {
			return nil, err
		}
		if present {
			out[k] = v
		}
	}
	return out, nil
}

func (a array) resolve(b *budget, vars map[string]any, path string) (any, bool, error) {
	out := make([]any, len(a))
	for i, child := range a {
		v, present, err := child.resolve(b, vars, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, false, err
		}
		if !present {
			// The binding says an absent optional omits "the field". An
			// array element is not a field, and dropping it would shift
			// every element after it into a position it was not written
			// for.
			return nil, false, mappingErr("%s[%d]: an optional expression is absent inside an array", path, i)
		}
		out[i] = v
	}
	return out, true, nil
}

// jsonValue converts a CEL result into the value it denotes in JSON. The
// binding requires an expression to evaluate to a single JSON value, so
// anything without a JSON form — bytes, a timestamp, a type — is an error
// rather than something given a string spelling here.
func jsonValue(v ref.Val, b *budget) (any, bool, error) {
	size := 0
	if s, ok := v.(types.String); ok {
		size = len(s)
	}
	if err := b.spend(size); err != nil {
		return nil, false, err
	}
	switch v := v.(type) {
	case *types.Optional:
		if !v.HasValue() {
			return nil, false, nil
		}
		return jsonValue(v.GetValue(), b)
	case types.Null:
		return nil, true, nil
	case types.Bool:
		return bool(v), true, nil
	case types.Int:
		return int64(v), true, nil
	case types.Uint:
		return uint64(v), true, nil
	case types.Double:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, false, fmt.Errorf("%v has no JSON representation", f)
		}
		return f, true, nil
	case types.String:
		return string(v), true, nil
	case traits.Lister:
		var out []any
		for it := v.Iterator(); it.HasNext() == types.True; {
			elem, present, err := jsonValue(it.Next(), b)
			if err != nil {
				return nil, false, err
			}
			if !present {
				return nil, false, errors.New("a list holds an absent optional")
			}
			out = append(out, elem)
		}
		if out == nil {
			out = []any{}
		}
		return out, true, nil
	case traits.Mapper:
		out := map[string]any{}
		for it := v.Iterator(); it.HasNext() == types.True; {
			key := it.Next()
			name, ok := key.(types.String)
			if !ok {
				return nil, false, fmt.Errorf("a map key of type %s has no JSON representation", key.Type().TypeName())
			}
			if err := b.spend(len(name)); err != nil {
				return nil, false, err
			}
			elem, present, err := jsonValue(v.Get(key), b)
			if err != nil {
				return nil, false, err
			}
			if present {
				out[string(name)] = elem
			}
		}
		return out, true, nil
	default:
		return nil, false, fmt.Errorf("a value of type %s has no JSON representation", v.Type().TypeName())
	}
}
