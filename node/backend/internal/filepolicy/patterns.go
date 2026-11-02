// Package filepolicy implements mount-level filename restrictions.
package filepolicy

import (
	"fmt"
	"path"
	"strings"
)

// ValidatePatterns accepts only basename globs. Reject malformed patterns at
// configuration load rather than silently treating them as non-matches.
func ValidatePatterns(patterns []string) error {
	if len(patterns) > 64 {
		return fmt.Errorf("at most 64 hidden patterns are allowed")
	}
	for _, pattern := range patterns {
		if pattern == "" || strings.ContainsAny(pattern, "/\\\x00") {
			return fmt.Errorf("hidden patterns must be non-empty basename globs")
		}
		if _, err := path.Match(strings.ToLower(pattern), "test"); err != nil {
			return fmt.Errorf("invalid hidden pattern %q: %w", pattern, err)
		}
	}
	return nil
}

func ValidateCanaries(paths []string) error {
	if len(paths) > 64 {
		return fmt.Errorf("at most 64 canary paths are allowed")
	}
	seen := map[string]bool{}
	for _, value := range paths {
		if value == "" || value == "." || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\\\x00") || path.IsAbs(value) || path.Clean(value) != value || value == ".." || strings.HasPrefix(value, "../") {
			return fmt.Errorf("canary paths must be normalized relative file paths")
		}
		if seen[value] {
			return fmt.Errorf("duplicate canary path")
		}
		seen[value] = true
	}
	return nil
}

func IsCanary(paths []string, relative string) bool {
	for _, value := range paths {
		if value == relative {
			return true
		}
	}
	return false
}

func Hidden(patterns []string, name string) bool {
	name = strings.ToLower(name)
	for _, pattern := range patterns {
		matched, err := path.Match(strings.ToLower(pattern), name)
		// Configured patterns are validated on startup. Fail closed if state is
		// damaged or a programmatic caller supplied a malformed pattern.
		if err != nil || matched {
			return true
		}
	}
	return false
}

// Internal reports names reserved for temporary or protected Jolt data.
func Internal(name string) bool {
	return strings.HasPrefix(name, ".jolt-") && strings.HasSuffix(name, ".partial") ||
		strings.HasPrefix(name, ".jolt-move-backup-") || name == ".jolt-trash"
}
