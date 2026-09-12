package verify

import (
	"fmt"
	"slices"

	"github.com/kanywst/mandatum/pkg/mda"
)

// checkAttenuation implements V5: every link must be no wider than its parent.
//
// The rules are deliberately one-directional. There is no path in this file
// that lets a child hold authority its parent did not, which is what makes
// "the sponsor's grant bounds everything below it" a property rather than a
// convention.
func checkAttenuation(chain Chain) error {
	for i := 1; i < len(chain); i++ {
		parent := chain[i-1].Claims
		child := chain[i].Claims

		if child.ExpiresAt > parent.ExpiresAt {
			return ruleErr("V5", i, fmt.Sprintf(
				"outlives its parent (exp %d > %d)", child.ExpiresAt, parent.ExpiresAt))
		}

		if child.Mandatum.MaxDepth > parent.Mandatum.MaxDepth-1 {
			return ruleErr("V5", i, fmt.Sprintf(
				"max_depth %d does not decrease from the parent's %d",
				child.Mandatum.MaxDepth, parent.Mandatum.MaxDepth))
		}

		if err := capsEntailed(parent.Mandatum.Capabilities, child.Mandatum.Capabilities); err != nil {
			return ruleErr("V5", i, err.Error())
		}

		if err := seqNoWider(parent.Mandatum.Sequence, child.Mandatum.Sequence); err != nil {
			return ruleErr("V5", i, err.Error())
		}
	}
	return nil
}

// capsEntailed reports whether every child capability is covered by some
// parent capability. A child capability matched by no parent capability is
// authority the parent never held.
func capsEntailed(parent, child []mda.Capability) error {
	for ci, c := range child {
		covered := false
		for _, p := range parent {
			if entails(p, c) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("cap[%d] (%s on %s/%s) is not covered by the parent's grant",
				ci, c.Action.Name, c.Resource.Type, c.Resource.ID)
		}
	}
	return nil
}

// entails reports whether parent capability p covers child capability c.
func entails(p, c mda.Capability) bool {
	if p.Resource.Type != c.Resource.Type {
		return false
	}
	if !idCovers(p.Resource.ID, c.Resource.ID) {
		return false
	}
	// Tags in a pattern are requirements. Requiring more tags matches fewer
	// resources, so the child must require at least everything the parent did.
	if !coversTags(p.Resource.Tags, c.Resource.Tags) {
		return false
	}
	if p.Action.Name != c.Action.Name {
		return false
	}
	// Every restriction the parent imposed must still be imposed, at least as
	// tightly. The child may add restrictions on keys the parent left free;
	// that narrows, so it is allowed.
	for key, pc := range p.Conditions {
		cc, ok := c.Conditions[key]
		if !ok {
			return false
		}
		if !condCovers(pc, cc) {
			return false
		}
	}
	return true
}

// idCovers reports whether pattern p covers pattern c. A trailing "*" makes a
// prefix pattern; anything else is a literal.
func idCovers(p, c string) bool {
	pPrefix, pIsPrefix := trimStar(p)
	cPrefix, cIsPrefix := trimStar(c)

	switch {
	case !pIsPrefix && !cIsPrefix:
		return p == c
	case pIsPrefix && !cIsPrefix:
		return hasPrefix(c, pPrefix)
	case pIsPrefix && cIsPrefix:
		// A longer prefix matches a subset of a shorter one.
		return hasPrefix(cPrefix, pPrefix)
	default:
		// A literal parent cannot cover a prefix child: the child would match
		// identifiers the parent never granted.
		return false
	}
}

func trimStar(s string) (string, bool) {
	if n := len(s); n > 0 && s[n-1] == '*' {
		return s[:n-1], true
	}
	return s, false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// coversTags reports whether child requires at least every tag parent required.
func coversTags(parent, child []string) bool {
	for _, want := range parent {
		if !slices.Contains(child, want) {
			return false
		}
	}
	return true
}

// condCovers reports whether child condition c is at least as restrictive as
// parent condition p.
//
// Comparison is only defined within the decidable fragment, and only between
// compatible kinds. Where restrictiveness cannot be decided, the answer is
// false: refusing a delegation the issuer believed was valid is recoverable,
// and accepting one that widens authority is not.
func condCovers(p, c mda.Condition) bool {
	switch {
	case p.Equals != nil:
		// Nothing is narrower than a fixed value except the same fixed value.
		return c.Equals != nil && *c.Equals == *p.Equals

	case p.In != nil:
		if c.Equals != nil {
			return inSet(p.In, *c.Equals)
		}
		if c.In != nil {
			for _, v := range c.In {
				if !inSet(p.In, v) {
					return false
				}
			}
			return true
		}
		return false

	case p.Prefix != nil:
		if c.Equals != nil {
			return hasPrefix(*c.Equals, *p.Prefix)
		}
		if c.Prefix != nil {
			return hasPrefix(*c.Prefix, *p.Prefix)
		}
		if c.In != nil {
			for _, v := range c.In {
				if !hasPrefix(v, *p.Prefix) {
					return false
				}
			}
			return true
		}
		return false

	case p.Min != nil || p.Max != nil:
		// A range child must be contained in the parent's range. An
		// unbounded child side is only acceptable where the parent is also
		// unbounded on that side.
		if c.Min == nil && c.Max == nil {
			return false
		}
		if p.Min != nil && (c.Min == nil || *c.Min < *p.Min) {
			return false
		}
		if p.Max != nil && (c.Max == nil || *c.Max > *p.Max) {
			return false
		}
		return true

	default:
		// A parent condition outside the fragment cannot be reasoned about.
		return false
	}
}

func inSet(set []string, v string) bool {
	return slices.Contains(set, v)
}

// seqNoWider reports whether the child's sequence constraints are at least as
// restrictive as the parent's.
//
// A parent that constrains a sequence binds every delegation below it; a child
// cannot drop the constraint by omitting the field, which is the obvious way
// someone would try.
func seqNoWider(parent, child *mda.Sequence) error {
	if parent == nil {
		return nil // The parent imposed no sequence limits; anything narrows.
	}
	if child == nil {
		return fmt.Errorf("drops the parent's sequence constraints entirely")
	}

	// MaxInvocations of 0 means unlimited, so a child may only be 0 if the
	// parent was.
	switch {
	case parent.MaxInvocations == 0:
		// Parent unlimited: any child budget narrows.
	case child.MaxInvocations == 0:
		return fmt.Errorf("removes the parent's invocation budget of %d", parent.MaxInvocations)
	case child.MaxInvocations > parent.MaxInvocations:
		return fmt.Errorf("raises the invocation budget from %d to %d",
			parent.MaxInvocations, child.MaxInvocations)
	}

	for _, pc := range parent.Constraints {
		found := false
		for _, cc := range child.Constraints {
			if cc.ID == pc.ID {
				found = true
				if !sameMatcher(cc.Forbid, pc.Forbid) || !sameMatcher(cc.After, pc.After) {
					return fmt.Errorf("redefines inherited sequence constraint %q", pc.ID)
				}
				break
			}
		}
		if !found {
			return fmt.Errorf("drops inherited sequence constraint %q", pc.ID)
		}
	}
	return nil
}

func sameMatcher(a, b mda.ActionMatcher) bool {
	return a.Action == b.Action &&
		a.ResourceType == b.ResourceType &&
		sameStrings(a.ResourceTags, b.ResourceTags)
}
