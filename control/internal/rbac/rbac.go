package rbac

import (
	"sort"
	"strings"

	"github.com/jfxdev/jolt/control/internal/filetypes"
)

var validCapabilities = map[string]struct{}{
	"read": {}, "list": {}, "create": {}, "update": {}, "delete": {},
	"write": {}, "execute": {}, "sudo": {}, "deny": {},
}

type Rule struct {
	Path         string              `json:"path"`
	Capabilities []string            `json:"capabilities"`
	FileTypes    *filetypes.Selector `json:"file_types,omitempty"`
	Visibility   string              `json:"visibility,omitempty"`
	// NeedsApproval lists capabilities this rule grants only once a person
	// approves each request. Only the destructive ones may be listed.
	NeedsApproval []string `json:"needs_approval,omitempty"`
}

type Policy struct {
	ID    string `json:"policy_id"`
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type Decision struct {
	// NeedsApproval is set on an allowed decision whose winning grant asks for a
	// person's approval. Callers that cannot collect one must treat it as denied.
	NeedsApproval bool     `json:"needs_approval,omitempty"`
	Allowed       bool     `json:"allowed"`
	Denied        bool     `json:"denied"`
	PolicyIDs     []string `json:"policy_ids"`
	Path          string   `json:"path"`
	Capability    string   `json:"capability"`
}

func ValidCapability(value string) bool {
	_, ok := validCapabilities[value]
	return ok
}

func NormalizePath(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if value == "workers" {
		return "nodes"
	}
	if strings.HasPrefix(value, "workers/") {
		return "nodes/" + strings.TrimPrefix(value, "workers/")
	}
	return value
}

// Recursive is the trailing wildcard that extends a rule over every descendant
// path. It is only meaningful as the last segment: "a/**" covers "a" and
// everything under it, while a "**" anywhere else is rejected so a policy can
// never read as broader than it looks.
const Recursive = "**"

func ValidPath(value string) bool {
	value = NormalizePath(value)
	if value == "" || strings.Contains(value, "//") {
		return false
	}
	segments := strings.Split(value, "/")
	for index, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		if segment == Recursive {
			// Only the final segment may be recursive.
			if index != len(segments)-1 {
				return false
			}
			continue
		}
		if segment == "*" {
			continue
		}
		for _, character := range segment {
			// File and directory names are user data: spaces, accented letters
			// and ordinary punctuation all occur legitimately, and a policy has
			// to be able to name them. Refused are the characters that would
			// break path parsing, smuggle a second segment, or let a policy
			// path read as a URL with a query string.
			if character < 0x20 || character == 0x7f {
				return false
			}
			if strings.ContainsRune(`\/?#&=%*`, character) {
				return false
			}
		}
	}
	return true
}

// ValidResourcePath validates a concrete path being authorized, as opposed to a
// policy rule being authored. Real file and directory names may contain the URL
// metacharacters that ValidPath refuses, so only the structural guarantees
// apply here: no empty segment, no traversal, no wildcard, no control
// character. Rejecting a legitimate name here would deny access to it.
func ValidResourcePath(value string) bool {
	value = NormalizePath(value)
	if value == "" || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		switch segment {
		case "", ".", "..", "*", Recursive:
			return false
		}
		for _, character := range segment {
			if character < 0x20 || character == 0x7f || character == '\\' {
				return false
			}
		}
	}
	return true
}

func Evaluate(policies []Policy, path, capability string) Decision {
	path = NormalizePath(path)
	capability = strings.ToLower(strings.TrimSpace(capability))
	decision := Decision{Path: path, Capability: capability}
	bestSpecificity := -1
	needsApproval := false
	allowedPolicies := map[string]struct{}{}
	deniedPolicies := map[string]struct{}{}

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			matches, specificity := match(rule.Path, path)
			if !matches {
				continue
			}
			capabilities := capabilitySet(rule.Capabilities)
			// This path-only evaluator cannot safely grant a typed rule. Treat
			// typed denies conservatively until the node applies the full filter.
			if rule.FileTypes != nil && !capabilities["deny"] {
				continue
			}
			if capabilities["deny"] {
				deniedPolicies[policy.ID] = struct{}{}
				continue
			}
			if !grants(capabilities, capability) {
				continue
			}
			marked := requiresApproval(rule, capability)
			if specificity > bestSpecificity {
				bestSpecificity = specificity
				needsApproval = marked
				allowedPolicies = map[string]struct{}{policy.ID: {}}
			} else if specificity == bestSpecificity {
				needsApproval = needsApproval || marked
				allowedPolicies[policy.ID] = struct{}{}
			}
		}
	}
	if len(deniedPolicies) > 0 {
		decision.Denied = true
		decision.PolicyIDs = sortedKeys(deniedPolicies)
		return decision
	}
	if len(allowedPolicies) > 0 {
		decision.Allowed = true
		decision.NeedsApproval = needsApproval
		decision.PolicyIDs = sortedKeys(allowedPolicies)
	}
	return decision
}

// ApprovalCapabilities are the capabilities a rule may ask a person to approve.
var ApprovalCapabilities = []string{"delete", "update"}

func requiresApproval(rule Rule, capability string) bool {
	for _, value := range rule.NeedsApproval {
		if strings.ToLower(strings.TrimSpace(value)) == capability {
			return true
		}
	}
	return false
}

// approvalMarked reports whether the most specific path rules that grant the
// capability ask for approval, ignoring denials: the typed evaluators decide
// allow and deny themselves and only need this mark from the path rules.
func approvalMarked(policies []Policy, path, capability string) bool {
	best, marked := -1, false
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			matches, specificity := match(rule.Path, path)
			capabilities := capabilitySet(rule.Capabilities)
			if !matches || rule.FileTypes != nil || capabilities["deny"] || !grants(capabilities, capability) {
				continue
			}
			if specificity > best {
				best, marked = specificity, requiresApproval(rule, capability)
			} else if specificity == best {
				marked = marked || requiresApproval(rule, capability)
			}
		}
	}
	return marked
}

// ValidNeedsApproval checks the approval marks of a rule: only destructive
// capabilities, each one the rule really grants, never on a denial, and not on
// a typed rule (the node cannot tell the Control Tower which entry needs it).
func ValidNeedsApproval(rule Rule) bool {
	if len(rule.NeedsApproval) == 0 {
		return true
	}
	capabilities := capabilitySet(rule.Capabilities)
	if capabilities["deny"] || rule.FileTypes != nil || rule.Visibility != "" || len(rule.NeedsApproval) > len(ApprovalCapabilities) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range rule.NeedsApproval {
		if value != strings.ToLower(strings.TrimSpace(value)) || seen[value] || !grants(capabilities, value) {
			return false
		}
		known := false
		for _, allowed := range ApprovalCapabilities {
			known = known || value == allowed
		}
		if !known {
			return false
		}
		seen[value] = true
	}
	return true
}

func grants(capabilities map[string]bool, requested string) bool {
	if capabilities[requested] {
		return true
	}
	return capabilities["write"] && (requested == "create" || requested == "update")
}

func capabilitySet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[strings.ToLower(strings.TrimSpace(value))] = true
	}
	return result
}

func match(pattern, path string) (bool, int) {
	patternParts := strings.Split(NormalizePath(pattern), "/")
	pathParts := strings.Split(NormalizePath(path), "/")
	recursive := patternParts[len(patternParts)-1] == Recursive
	if recursive {
		// "a/b/**" covers "a/b" itself and every path beneath it, so the fixed
		// prefix is what has to line up and the path may be longer.
		patternParts = patternParts[:len(patternParts)-1]
		if len(pathParts) < len(patternParts) {
			return false, 0
		}
	} else if len(patternParts) != len(pathParts) {
		return false, 0
	}
	specificity := 0
	for index, part := range patternParts {
		if part == "*" {
			continue
		}
		if part != pathParts[index] {
			return false, 0
		}
		specificity += 100 + len(part)
	}
	// A recursive rule is deliberately less specific than an exact rule that
	// matches the same path, so "photos/**: read" loses to
	// "photos/private: deny-by-omission" style narrowing at equal depth.
	if recursive {
		return true, specificity
	}
	return true, specificity + len(patternParts)
}

// DeniesWithin reports whether any deny rule applies to a path at or below
// scope.
//
// It exists for operations that read a whole subtree in one request — a ZIP of
// a folder, a recursive search — where the caller names only the subtree root.
// Evaluating the root alone would authorize the request while the node happily
// read descendants the subject is denied, so deny would stop winning globally.
// The node cannot filter them itself: it does not know the subject's policies.
// Callers therefore refuse the whole operation when this returns true, and the
// subject narrows the request to an allowed subfolder.
func DeniesWithin(policies []Policy, scope string) bool {
	scopeParts := strings.Split(NormalizePath(scope), "/")
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if !capabilitySet(rule.Capabilities)["deny"] {
				continue
			}
			if denyReachesScope(strings.Split(NormalizePath(rule.Path), "/"), scopeParts) {
				return true
			}
		}
	}
	return false
}

// UntypedDeniesWithin preserves the subtree refusal for path-based denials
// when a node will enforce typed rules per entry. The original DeniesWithin
// remains conservative for operations without verified node filtering.
func UntypedDeniesWithin(policies []Policy, scope string) bool {
	if !ValidResourcePath(scope) {
		return true
	}
	scopeParts := strings.Split(NormalizePath(scope), "/")
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if rule.FileTypes != nil || !capabilitySet(rule.Capabilities)["deny"] {
				continue
			}
			if !ValidPath(rule.Path) || denyReachesScope(strings.Split(NormalizePath(rule.Path), "/"), scopeParts) {
				return true
			}
		}
	}
	return false
}

// RuleTouchesScope reports whether a rule can match the named scope or a
// descendant. Callers must validate both paths before using this to narrow a
// security context; invalid input is conservatively treated as touching it.
func RuleTouchesScope(rulePath, scope string) bool {
	if !ValidPath(rulePath) || !ValidResourcePath(scope) {
		return true
	}
	return denyReachesScope(strings.Split(NormalizePath(rulePath), "/"), strings.Split(NormalizePath(scope), "/"))
}

// denyReachesScope reports whether a deny rule covers the scope itself or
// anything under it. The rule's fixed prefix must agree with the scope on every
// segment they share; a "*" agrees with anything. A rule shorter than the scope
// only reaches it when it is recursive, otherwise it names an ancestor and
// matching is exact elsewhere.
func denyReachesScope(ruleParts, scopeParts []string) bool {
	recursive := ruleParts[len(ruleParts)-1] == Recursive
	if recursive {
		ruleParts = ruleParts[:len(ruleParts)-1]
	}
	shared := len(ruleParts)
	if len(scopeParts) < shared {
		shared = len(scopeParts)
	}
	for index := 0; index < shared; index++ {
		if ruleParts[index] == "*" || scopeParts[index] == "*" {
			continue
		}
		if ruleParts[index] != scopeParts[index] {
			return false
		}
	}
	if len(ruleParts) >= len(scopeParts) {
		// The rule is at or below the scope: it denies something being read.
		return true
	}
	// The rule sits above the scope and only reaches into it when recursive.
	return recursive
}

// ExpandCompatibilityRules keeps policies written before recursive paths
// existed working unchanged. A rule that stops exactly at a mount
// ("nodes/<id>/files/mounts/<mountID>") used to authorize every path inside
// that mount, because file operations were evaluated at mount granularity.
// Now that they are evaluated per subpath, the same rule is also published as
// its recursive form so the effective access it already granted is preserved.
// Deny rules expand too, so narrowing a legacy policy never loosens.
func ExpandCompatibilityRules(policies []Policy) []Policy {
	expanded := make([]Policy, 0, len(policies))
	for _, policy := range policies {
		rules := make([]Rule, 0, len(policy.Rules))
		for _, rule := range policy.Rules {
			rules = append(rules, rule)
			if isMountScopedFileRule(rule.Path) {
				compatibility := rule
				compatibility.Path = NormalizePath(rule.Path) + "/" + Recursive
				rules = append(rules, compatibility)
			}
		}
		policy.Rules = rules
		expanded = append(expanded, policy)
	}
	return expanded
}

// isMountScopedFileRule reports whether path names a whole mount in the file
// family: nodes/<nodeID>/files/mounts/<mountID>, with nothing after it.
func isMountScopedFileRule(path string) bool {
	segments := strings.Split(NormalizePath(path), "/")
	return len(segments) == 5 && segments[0] == "nodes" &&
		segments[2] == "files" && segments[3] == "mounts"
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// RuleMatch is a rule that bears on a decision, for diagnosis.
type RuleMatch struct {
	PolicyID      string              `json:"policy_id"`
	Path          string              `json:"path"`
	Capabilities  []string            `json:"capabilities"`
	Effect        string              `json:"effect"`
	FileTypes     *filetypes.Selector `json:"file_types,omitempty"`
	Visibility    string              `json:"visibility,omitempty"`
	NeedsApproval []string            `json:"needs_approval,omitempty"`
}

// MatchingRules lists the rules that cover the path and bear on the capability,
// with the effect each one has: allow, deny, typed_allow or typed_deny. It does
// not decide anything; it shows what the decision was made from. A rule that
// covers the path but says nothing about the capability is left out.
func MatchingRules(policies []Policy, path, capability string) []RuleMatch {
	path = NormalizePath(path)
	capability = strings.ToLower(strings.TrimSpace(capability))
	var matches []RuleMatch
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			covers, _ := match(rule.Path, path)
			if !covers {
				continue
			}
			capabilities := capabilitySet(rule.Capabilities)
			effect := ""
			switch {
			case capabilities["deny"] && rule.FileTypes == nil:
				effect = "deny"
			case capabilities["deny"] && (len(capabilities) == 1 || grants(capabilities, capability)):
				effect = "typed_deny"
			case !capabilities["deny"] && grants(capabilities, capability) && rule.FileTypes != nil:
				effect = "typed_allow"
			case !capabilities["deny"] && grants(capabilities, capability):
				effect = "allow"
			}
			if effect == "" {
				continue
			}
			matches = append(matches, RuleMatch{PolicyID: policy.ID, Path: NormalizePath(rule.Path), Capabilities: append([]string(nil), rule.Capabilities...),
				Effect: effect, FileTypes: rule.FileTypes, Visibility: rule.Visibility, NeedsApproval: append([]string(nil), rule.NeedsApproval...)})
		}
	}
	return matches
}
