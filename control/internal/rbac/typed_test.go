package rbac

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/jfxdev/jolt/control/internal/filetypes"
)

const mountPath = "nodes/n/files/mounts/m"

func typedPolicy(id string, rules ...Rule) Policy { return Policy{ID: id, Rules: rules} }

func TestWithoutTypedRulesEvaluateTypedIsTheLegacyEvaluator(t *testing.T) {
	policies := ExpandCompatibilityRules([]Policy{
		typedPolicy("a", Rule{Path: mountPath, Capabilities: []string{"read", "list"}}, Rule{Path: mountPath + "/private/**", Capabilities: []string{"deny"}}),
		typedPolicy("b", Rule{Path: mountPath + "/inbox/**", Capabilities: []string{"write"}}, Rule{Path: "nodes/*/transfers", Capabilities: []string{"execute"}}),
	})
	for _, path := range []string{mountPath, mountPath + "/docs/a.txt", mountPath + "/private", mountPath + "/private/x", mountPath + "/inbox/f", "nodes/n/transfers", "nodes/x/transfers", "workers/n"} {
		for _, capability := range []string{"read", "list", "create", "update", "delete", "execute"} {
			want := Evaluate(policies, path, capability)
			for _, mode := range []EntryMode{EveryEntry, NodeFiltered} {
				if got := EvaluateTyped(policies, path, capability, mode); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s %s mode=%d: %+v want %+v", path, capability, mode, got, want)
				}
			}
		}
	}
}

func TestTypedAllowGrantsOnlyMatchingFilesAndKeepsDirectoriesNavigable(t *testing.T) {
	video := &filetypes.Selector{Classes: []string{"video"}}
	policies := []Policy{typedPolicy("videos", Rule{Path: mountPath + "/movies/**", Capabilities: []string{"read", "list"}, FileTypes: video})}
	// A typed allow authorizes by path for directories and by type for files, so
	// whether a bare path is allowed depends on what the node finds there.
	for _, test := range []struct {
		path            string
		every, filtered bool
	}{
		{mountPath + "/movies/a.mkv", true, true},      // a video, or a directory by that name
		{mountPath + "/movies/notes.txt", false, true}, // not a video as a file
		{mountPath + "/movies", false, true},
		{mountPath + "/music/a.mp3", false, false}, // outside the rule entirely
	} {
		for mode, want := range map[EntryMode]bool{EveryEntry: test.every, NodeFiltered: test.filtered} {
			if got := EvaluateTyped(policies, test.path, "read", mode); got.Allowed != want || got.Denied {
				t.Fatalf("%s mode=%d: %+v want allowed=%v", test.path, mode, got, want)
			}
		}
	}
}

func TestTypedDenyHidesOnlyMatchingFilesWhereTheNodeFilters(t *testing.T) {
	pem := &filetypes.Selector{Extensions: []string{"pem"}}
	policies := ExpandCompatibilityRules([]Policy{
		typedPolicy("base", Rule{Path: mountPath, Capabilities: []string{"read", "list"}}),
		typedPolicy("no-keys", Rule{Path: mountPath + "/**", Capabilities: []string{"deny", "read"}, FileTypes: pem}),
	})
	cases := []struct {
		path                            string
		capability                      string
		everyAllowed, everyDenied       bool
		filteredAllowed, filteredDenied bool
	}{
		// A key file is denied for reading wherever the entry is a file; as a
		// directory it would be allowed, which only the node can tell.
		{mountPath + "/ssh/id.pem", "read", false, true, true, false},
		{mountPath + "/ssh/id.txt", "read", true, false, true, false},
		{mountPath + "/ssh", "read", true, false, true, false},
		// The denial lists only read: listing a key file's name stays allowed.
		{mountPath + "/ssh/id.pem", "list", true, false, true, false},
	}
	for _, c := range cases {
		every := EvaluateTyped(policies, c.path, c.capability, EveryEntry)
		filtered := EvaluateTyped(policies, c.path, c.capability, NodeFiltered)
		if every.Allowed != c.everyAllowed || every.Denied != c.everyDenied || filtered.Allowed != c.filteredAllowed || filtered.Denied != c.filteredDenied {
			t.Fatalf("%s %s: every=%+v filtered=%+v", c.path, c.capability, every, filtered)
		}
	}
}

func TestPathDenialsStayDeniedInBothModesAndFailuresAreClosed(t *testing.T) {
	pem := &filetypes.Selector{Extensions: []string{"pem"}}
	policies := []Policy{typedPolicy("p",
		Rule{Path: mountPath + "/**", Capabilities: []string{"read", "list"}},
		Rule{Path: mountPath + "/vault/**", Capabilities: []string{"deny"}},
		Rule{Path: mountPath + "/**", Capabilities: []string{"deny", "read"}, FileTypes: pem},
	)}
	for _, mode := range []EntryMode{EveryEntry, NodeFiltered} {
		if got := EvaluateTyped(policies, mountPath+"/vault/x.txt", "read", mode); got.Allowed || !got.Denied {
			t.Fatalf("mode=%d path denial: %+v", mode, got)
		}
	}
	// More rules than a context can carry: the conservative evaluator decides.
	var rules []Rule
	for i := 0; i < filetypes.MaxContextRules+5; i++ {
		rules = append(rules, Rule{Path: fmt.Sprintf("%s/**", mountPath), Capabilities: []string{"read"}, FileTypes: &filetypes.Selector{Extensions: []string{"x"}}})
	}
	got := EvaluateTyped([]Policy{typedPolicy("many", rules...)}, mountPath+"/a.x", "read", NodeFiltered)
	if got.Allowed {
		t.Fatalf("an oversized context granted access: %+v", got)
	}
	// A path the evaluator cannot judge is never allowed by a typed rule.
	if got := EvaluateTyped(policies, mountPath+"/a/*/b", "read", NodeFiltered); got.Allowed {
		t.Fatalf("a wildcard resource was allowed: %+v", got)
	}
	if !HasTypedRules(policies, mountPath+"/a.txt") || HasTypedRules(policies, "nodes/other/files/mounts/m/a.txt") {
		t.Fatal("HasTypedRules misjudged which paths a typed rule covers")
	}
}

func TestEvaluateEntryAnswersForTheKnownTypeAndSaysHowADenialShows(t *testing.T) {
	pem := &filetypes.Selector{Extensions: []string{"pem"}}
	video := &filetypes.Selector{Classes: []string{"video"}}
	policies := ExpandCompatibilityRules([]Policy{
		typedPolicy("base", Rule{Path: mountPath, Capabilities: []string{"read", "list"}}),
		typedPolicy("no-keys", Rule{Path: mountPath + "/**", Capabilities: []string{"deny", "read"}, FileTypes: pem, Visibility: "visible"}),
		typedPolicy("videos", Rule{Path: mountPath + "/movies/**", Capabilities: []string{"write"}, FileTypes: video}),
	})
	for _, test := range []struct {
		path, capability, entry, visibility string
		allowed, denied                     bool
	}{
		{mountPath + "/a.pem", "read", "file", "visible", false, true},
		{mountPath + "/a.pem", "read", "directory", "", true, false}, // a directory is not a key
		{mountPath + "/a.pem", "list", "file", "", true, false},      // the denial lists only read
		{mountPath + "/a.txt", "read", "file", "", true, false},
		{mountPath + "/movies/a.mkv", "write", "file", "", true, false},
		{mountPath + "/movies/a.txt", "write", "file", "", false, false},
	} {
		got := EvaluateEntry(policies, test.path, test.capability, test.entry)
		if got.Allowed != test.allowed || got.Denied != test.denied || got.Visibility != test.visibility || !got.Typed {
			t.Fatalf("%s %s %s: %+v", test.path, test.capability, test.entry, got)
		}
	}
	plain := EvaluateEntry([]Policy{typedPolicy("p", Rule{Path: mountPath, Capabilities: []string{"read"}})}, mountPath, "read", "directory")
	if !plain.Allowed || plain.Typed || plain.Visibility != "" {
		t.Fatalf("without typed rules the answer is the legacy one: %+v", plain)
	}
}
