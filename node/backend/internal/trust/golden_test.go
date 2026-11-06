package trust

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The same corpus the Control Tower's tests read: both copies of the verifier
// must give every bundle the same answer.
type goldenBundleCase struct {
	Name     string          `json:"name"`
	Bundle   json.RawMessage `json:"bundle"`
	Previous json.RawMessage `json:"previous,omitempty"`
	Pin      string          `json:"pin,omitempty"`
	Now      time.Time       `json:"now"`
	Accepted bool            `json:"accepted"`
}

func TestGoldenBundleCasesAgreeWithTheVerifier(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "trust-bundle-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenBundleCase
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) < 25 {
		t.Fatalf("golden file: %d cases, %v", len(cases), err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			candidate, err := ParseBundle(c.Bundle)
			if err != nil {
				if c.Accepted {
					t.Fatalf("a bundle that must be accepted does not parse: %v", err)
				}
				return
			}
			var previous *Bundle
			if len(c.Previous) > 0 {
				parsed, err := ParseBundle(c.Previous)
				if err != nil {
					t.Fatal(err)
				}
				previous = &parsed
			}
			err = VerifyBundle(candidate, previous, c.Pin, c.Now)
			if c.Accepted && err != nil {
				t.Fatalf("must be accepted: %v", err)
			}
			if !c.Accepted && err == nil {
				t.Fatal("must be refused")
			}
		})
	}
}
