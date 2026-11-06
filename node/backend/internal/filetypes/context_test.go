package filetypes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedContextCases(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	for {
		data, err = os.ReadFile(filepath.Join(dir, "testdata", "filetype-context-cases.json"))
		if err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("shared context cases not found: %v", err)
		}
		dir = parent
	}
	var cases []struct {
		Name       string          `json:"name"`
		Context    json.RawMessage `json:"context"`
		Resource   string          `json:"resource"`
		Capability string          `json:"capability"`
		IsFile     bool            `json:"is_file"`
		Allowed    bool            `json:"allowed"`
		Denied     bool            `json:"denied"`
		Visibility string          `json:"visibility"`
		Restricted *bool           `json:"restricted"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			filter, err := DecodeContext(tc.Context)
			if err != nil {
				t.Fatal(err)
			}
			kind := "directory"
			if tc.IsFile {
				kind = "file"
			}
			got := filter.Evaluate(tc.Resource, tc.Capability, kind)
			if got.Allowed != tc.Allowed || got.Denied != tc.Denied || got.Visibility != tc.Visibility {
				t.Fatalf("decision=%+v", got)
			}
			if tc.Restricted != nil && got.Restricted != *tc.Restricted {
				t.Fatalf("restriction=%+v", got)
			}
		})
	}
}

func TestContextRejectsUnsupportedOrMalformedInput(t *testing.T) {
	for _, input := range []string{
		`{"version":2,"rules":[]}`,
		`{"version":1,"rules":[],"unsupported":true}`,
		`{"version":1,"rules":[]} {}`,
		`{"version":2,"Version":1,"rules":[]}`,
		`{"version":1,"rules":[{"policy_id":"p","path":"nodes/**","capabilities":["read"],"file_types":{"names":["a"],"Names":["b"]}}]}`,
		`{"version":1,"rules":[{"policy_id":"p","path":"nodes/**/x","capabilities":["read"]}]}`,
		`{"version":1,"rules":[{"policy_id":"p","path":"nodes/**","capabilities":["read"],"file_types":{}}]}`,
		`{"version":1,"rules":[{"policy_id":"p","path":"nodes/**","capabilities":["read"],"visibility":"other"}]}`,
		strings.Repeat(" ", MaxContextBytes+1),
	} {
		if _, err := DecodeContext([]byte(input)); err == nil {
			t.Fatalf("accepted invalid context %q", input[:min(len(input), 120)])
		}
	}
	rules := make([]Rule, MaxContextRules+1)
	for i := range rules {
		rules[i] = Rule{PolicyID: "p", Path: "nodes/**", Capabilities: []string{"read"}}
	}
	if _, err := (Context{Version: 1, Rules: rules}).Compile(); err == nil {
		t.Fatal("accepted excessive rules")
	}
	filter, err := DecodeContext([]byte(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/**","capabilities":["read"]}]}`))
	if err != nil || filter.Evaluate("nodes/n/link", "read", "symlink").Allowed {
		t.Fatal("unrecognized entry type was accepted")
	}
}
