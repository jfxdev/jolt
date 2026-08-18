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

func ValidPath(value string) bool {
	value = NormalizePath(value)
	if value == "" || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		if segment == "*" {
			continue
		}
		for _, character := range segment {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
				continue
			}
			return false
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
	if len(patternParts) != len(pathParts) {
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
	return true, specificity + len(patternParts)
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
