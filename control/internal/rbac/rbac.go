package rbac

import (
	"sort"
	"strings"
)

var validCapabilities = map[string]struct{}{
	"read": {}, "list": {}, "create": {}, "update": {}, "delete": {},
	"write": {}, "execute": {}, "sudo": {}, "deny": {},
}

type Rule struct {
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
}

type Policy struct {
	ID    string `json:"policy_id"`
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type Decision struct {
	Allowed    bool     `json:"allowed"`
	Denied     bool     `json:"denied"`
	PolicyIDs  []string `json:"policy_ids"`
	Path       string   `json:"path"`
	Capability string   `json:"capability"`
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
	allowedPolicies := map[string]struct{}{}
	deniedPolicies := map[string]struct{}{}

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			matches, specificity := match(rule.Path, path)
			if !matches {
				continue
			}
			capabilities := capabilitySet(rule.Capabilities)
			if capabilities["deny"] {
				deniedPolicies[policy.ID] = struct{}{}
				continue
			}
			if !grants(capabilities, capability) {
				continue
			}
			if specificity > bestSpecificity {
				bestSpecificity = specificity
				allowedPolicies = map[string]struct{}{policy.ID: {}}
			} else if specificity == bestSpecificity {
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
		decision.PolicyIDs = sortedKeys(allowedPolicies)
	}
	return decision
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
				rules = append(rules, Rule{
					Path:         NormalizePath(rule.Path) + "/" + Recursive,
					Capabilities: rule.Capabilities,
				})
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
