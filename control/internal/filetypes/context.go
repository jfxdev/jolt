package filetypes

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

const MaxContextBytes = 32 << 10
const MaxContextRules = 256

type Rule struct {
	PolicyID     string    `json:"policy_id"`
	Path         string    `json:"path"`
	Capabilities []string  `json:"capabilities"`
	FileTypes    *Selector `json:"file_types,omitempty"`
	Visibility   string    `json:"visibility,omitempty"`
}

type Context struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

type compiledRule struct {
	rule    Rule
	matcher *Matcher
	caps    map[string]bool
}

type Filter struct{ rules []compiledRule }

type Decision struct {
	Allowed    bool   `json:"allowed"`
	Denied     bool   `json:"denied"`
	Visibility string `json:"visibility"`
}

var validCaps = set("read", "list", "create", "update", "delete", "write", "execute", "sudo", "deny")

// DecodeContext rejects unknown fields, invalid versions and excessive input.
func DecodeContext(data []byte) (*Filter, error) {
	if len(data) == 0 || len(data) > MaxContextBytes {
		return nil, errors.New("invalid context size")
	}
	if err := validateUniqueJSON(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ctx Context
	if err := decoder.Decode(&ctx); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing context data")
	}
	return ctx.Compile()
}

func validateUniqueJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var readValue func(int) error
	readValue = func(depth int) error {
		if depth > 64 {
			return errors.New("context nesting is excessive")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				name = strings.ToLower(name)
				if !ok || seen[name] {
					return errors.New("duplicate context field")
				}
				seen[name] = true
				if err := readValue(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := readValue(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid context delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := readValue(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing context data")
	}
	return nil
}

// ValidateUniqueJSON rejects duplicate keys and excessive nesting before
// security-sensitive JSON is decoded into a struct.
func ValidateUniqueJSON(data []byte) error { return validateUniqueJSON(data) }

func (c Context) Compile() (*Filter, error) {
	if c.Version != 1 || len(c.Rules) > MaxContextRules {
		return nil, errors.New("unsupported context")
	}
	encoded, err := json.Marshal(c)
	if err != nil || len(encoded) > MaxContextBytes {
		return nil, errors.New("invalid context size")
	}
	filter := &Filter{rules: make([]compiledRule, 0, len(c.Rules))}
	for _, rule := range c.Rules {
		if rule.PolicyID == "" || len(rule.PolicyID) > 128 || !utf8.ValidString(rule.PolicyID) || strings.ContainsAny(rule.PolicyID, "/\\\x00") || !validPattern(rule.Path) || len(rule.Capabilities) == 0 || len(rule.Capabilities) > len(validCaps) {
			return nil, errors.New("invalid rule")
		}
		if rule.Visibility == "" {
			rule.Visibility = "hidden"
		}
		if rule.Visibility != "hidden" && rule.Visibility != "visible" {
			return nil, errors.New("invalid visibility")
		}
		compiled := compiledRule{rule: rule, caps: map[string]bool{}}
		for _, cap := range rule.Capabilities {
			cap = strings.ToLower(strings.TrimSpace(cap))
			if !validCaps[cap] || compiled.caps[cap] {
				return nil, errors.New("invalid capability")
			}
			compiled.caps[cap] = true
		}
		if rule.FileTypes != nil {
			var err error
			compiled.matcher, err = rule.FileTypes.Compile()
			if err != nil {
				return nil, err
			}
		}
		filter.rules = append(filter.rules, compiled)
	}
	return filter, nil
}

func validPattern(value string) bool {
	value = strings.Trim(value, "/")
	if value == "" || !utf8.ValidString(value) || strings.Contains(value, "//") {
		return false
	}
	parts := strings.Split(value, "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." || part == "**" && i != len(parts)-1 {
			return false
		}
		if part == "*" || part == "**" {
			continue
		}
		for _, ch := range part {
			if ch < 0x20 || ch == 0x7f || strings.ContainsRune(`\/?#&=%*`, ch) {
				return false
			}
		}
	}
	return true
}

func matchPath(pattern, value string) (bool, int) {
	parts := strings.Split(strings.Trim(pattern, "/"), "/")
	target := strings.Split(strings.Trim(value, "/"), "/")
	recursive := parts[len(parts)-1] == "**"
	if recursive {
		parts = parts[:len(parts)-1]
		if len(target) < len(parts) {
			return false, 0
		}
	} else if len(parts) != len(target) {
		return false, 0
	}
	score := 0
	for i, part := range parts {
		if part == "*" {
			continue
		}
		if part != target[i] {
			return false, 0
		}
		score += 100 + len(part)
	}
	if !recursive {
		score += len(parts)
	}
	return true, score
}

func grants(caps map[string]bool, capability string) bool {
	return caps[capability] || caps["write"] && (capability == "create" || capability == "update")
}

func validResource(value string) bool {
	value = strings.Trim(value, "/")
	if value == "" || !utf8.ValidString(value) || strings.Contains(value, "//") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || part == "*" || part == "**" {
			return false
		}
		for _, ch := range part {
			if ch < 0x20 || ch == 0x7f || ch == '\\' {
				return false
			}
		}
	}
	return true
}

// Evaluate applies path precedence and deny-wins semantics. Typed denies apply
// only to regular files; typed allows authorize directories by path so they
// remain navigable. Unknown entry types fail closed.
func (f *Filter) Evaluate(resource, capability, entryType string) Decision {
	result := Decision{Visibility: "hidden"}
	capability = strings.ToLower(strings.TrimSpace(capability))
	if f == nil || !validResource(resource) || !validCaps[capability] || capability == "deny" || entryType != "file" && entryType != "directory" {
		return result
	}
	best, found, restricted, anyHidden := -1, false, false, false
	for _, compiled := range f.rules {
		matchesPath, specificity := matchPath(compiled.rule.Path, resource)
		if !matchesPath {
			continue
		}
		typed := compiled.matcher != nil
		if typed && entryType == "directory" && compiled.caps["deny"] {
			continue
		}
		matchesType := !typed || entryType == "directory" || compiled.matcher.Matches(path.Base(resource), true)
		deny := compiled.caps["deny"] && (!typed || len(compiled.caps) == 1 || grants(compiled.caps, capability))
		allow := !compiled.caps["deny"] && grants(compiled.caps, capability)
		if typed && !matchesType && allow && (capability == "read" || capability == "list") {
			restricted = true
			anyHidden = anyHidden || compiled.rule.Visibility == "hidden"
		}
		if !matchesType {
			continue
		}
		if deny {
			result.Denied = true
			if capability == "read" || capability == "list" {
				restricted = true
				anyHidden = anyHidden || compiled.rule.Visibility == "hidden"
			}
			continue
		}
		if allow && specificity >= best {
			best, found = specificity, true
		}
	}
	if restricted && !anyHidden {
		result.Visibility = "visible"
	}
	result.Allowed = found && !result.Denied
	return result
}
