package filetypes

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedSelectorCases(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	for {
		data, err = os.ReadFile(filepath.Join(dir, "testdata", "filetype-selectors.json"))
		if err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("shared selector cases not found: %v", err)
		}
		dir = parent
	}
	var cases []struct {
		Name     string   `json:"name"`
		Selector Selector `json:"selector"`
		Entry    string   `json:"entry"`
		IsFile   bool     `json:"is_file"`
		Valid    bool     `json:"valid"`
		Matches  bool     `json:"matches"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if valid := tc.Selector.Validate() == nil; valid != tc.Valid {
				t.Fatalf("valid=%t want %t", valid, tc.Valid)
			}
			if matched := tc.Selector.Matches(tc.Entry, tc.IsFile); matched != tc.Matches {
				t.Fatalf("matches=%t want %t", matched, tc.Matches)
			}
			matcher, err := tc.Selector.Compile()
			if (err == nil) != tc.Valid {
				t.Fatalf("compile error=%v", err)
			}
			if err == nil && matcher.Matches(tc.Entry, tc.IsFile) != tc.Matches {
				t.Fatalf("compiled matcher diverged")
			}
		})
	}
}

func TestSelectorCountIsNeverTruncated(t *testing.T) {
	selector := Selector{}
	for i := 0; i < 64; i++ {
		selector.Names = append(selector.Names, fmt.Sprintf("name-%d", i))
	}
	if err := selector.Validate(); err != nil {
		t.Fatal(err)
	}
	selector.Names = append(selector.Names, "overflow")
	if selector.Validate() == nil || selector.Matches("name-0", true) {
		t.Fatal("excessive selector was accepted")
	}
}
