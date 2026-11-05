package rbac

import (
	"github.com/jfxdev/jolt/control/internal/filetypes"
)

// EntryMode says how much the caller knows about the entry a path names and who
// will enforce typed rules for it.
type EntryMode int

const (
	// EveryEntry is for operations the node does not filter per entry. The path
	// may name a file or a directory, so the operation is allowed only when it
	// would be allowed for both, and it is denied when either is denied.
	EveryEntry EntryMode = iota
	// NodeFiltered is for operations the node enforces with the signed policy
	// context, entry by entry. The Control Tower only refuses what could never
	// be allowed: it allows when some kind of entry may be and denies only when
	// every kind is denied, leaving the real type to the node.
	NodeFiltered
)

// ruleMatches reports whether a rule's path pattern covers the path.
func ruleMatches(rule Rule, path string) bool {
	matches, _ := match(rule.Path, path)
	return matches
}

// HasTypedRules reports whether any rule covering the path carries a file type
// selector or a visibility, i.e. whether the path-only evaluator is not enough.
func HasTypedRules(policies []Policy, path string) bool {
	path = NormalizePath(path)
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if (rule.FileTypes != nil || rule.Visibility != "") && ruleMatches(rule, path) {
				return true
			}
		}
	}
	return false
}

// EvaluateTyped decides path and capability with typed rules, using the same
// evaluator the node applies to a signed context so both sides agree. Without a
// typed rule covering the path it is exactly Evaluate. Anything it cannot
// evaluate (an invalid path or rule, too many rules) fails closed to the
// conservative path-only evaluator, which denies a typed deny outright and
// ignores a typed allow.
func EvaluateTyped(policies []Policy, path, capability string, mode EntryMode) Decision {
	path = NormalizePath(path)
	if !HasTypedRules(policies, path) {
		return Evaluate(policies, path, capability)
	}
	conservative := Evaluate(policies, path, capability)
	filter, ok := compileTyped(policies, path)
	if !ok {
		return conservative
	}
	file, directory := filter.Evaluate(path, capability, "file"), filter.Evaluate(path, capability, "directory")
	decision := Decision{Path: path, Capability: capability, PolicyIDs: matchingPolicyIDs(policies, path)}
	if mode == NodeFiltered {
		decision.Allowed = file.Allowed || directory.Allowed
		decision.Denied = file.Denied && directory.Denied
	} else {
		decision.Allowed = file.Allowed && directory.Allowed
		decision.Denied = file.Denied || directory.Denied
	}
	if decision.Denied {
		decision.Allowed = false
	}
	// Approval marks live on path rules the typed evaluator does not read; ask
	// the path evaluator so a typed rule on the same path cannot drop one.
	decision.NeedsApproval = decision.Allowed && approvalMarked(policies, path, capability)
	return decision
}

// compileTyped builds the node's evaluator from the rules covering the path. It
// reports false when the rules cannot be evaluated, so callers fail closed.
func compileTyped(policies []Policy, path string) (*filetypes.Filter, bool) {
	context := filetypes.Context{Version: 1, Rules: []filetypes.Rule{}}
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if !ruleMatches(rule, path) {
				continue
			}
			if !ValidPath(rule.Path) {
				return nil, false
			}
			context.Rules = append(context.Rules, filetypes.Rule{
				PolicyID: policy.ID, Path: NormalizePath(rule.Path), Capabilities: append([]string(nil), rule.Capabilities...),
				FileTypes: rule.FileTypes, Visibility: rule.Visibility,
			})
		}
	}
	filter, err := context.Compile()
	if err != nil || !ValidResourcePath(path) {
		return nil, false
	}
	return filter, true
}

// EntryDecision is what the node decides for one entry whose type is known.
// Visibility says, for a denied read or list that a typed rule caused, whether
// the entry disappears ("hidden") or is shown but blocked ("visible").
type EntryDecision struct {
	Decision
	Visibility string `json:"visibility,omitempty"`
	Typed      bool   `json:"typed"`
}

// EvaluateEntry answers what the node would do with a file or directory at path,
// given the type the node would find there. Unlike EvaluateTyped it does not
// have to guess the type, so it is the exact answer for that entry. Anything it
// cannot evaluate fails closed, as EvaluateTyped does.
func EvaluateEntry(policies []Policy, path, capability, entryType string) EntryDecision {
	path = NormalizePath(path)
	if !HasTypedRules(policies, path) {
		return EntryDecision{Decision: Evaluate(policies, path, capability)}
	}
	conservative := EntryDecision{Decision: Evaluate(policies, path, capability), Typed: true}
	filter, ok := compileTyped(policies, path)
	if !ok {
		return conservative
	}
	result := filter.Evaluate(path, capability, entryType)
	decision := EntryDecision{
		Decision: Decision{Allowed: result.Allowed && !result.Denied, Denied: result.Denied, Path: path, Capability: capability, PolicyIDs: matchingPolicyIDs(policies, path)},
		Typed:    true,
	}
	if result.Restricted && !decision.Allowed {
		decision.Visibility = result.Visibility
	}
	decision.NeedsApproval = decision.Allowed && approvalMarked(policies, path, capability)
	return decision
}

// matchingPolicyIDs lists the policies with a rule covering the path, for audit.
func matchingPolicyIDs(policies []Policy, path string) []string {
	ids := map[string]struct{}{}
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if ruleMatches(rule, path) {
				ids[policy.ID] = struct{}{}
			}
		}
	}
	return sortedKeys(ids)
}
