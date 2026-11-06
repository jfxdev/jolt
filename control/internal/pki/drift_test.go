package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The node cannot import this package, so it carries copies of the bundle
// verifier and its certificate helpers. They differ only in the package name and
// the import path of signedauth. A fix applied to one copy and not the other
// would make the node accept or refuse what the Control Tower does not.
func TestTheNodeCopiesOfTheVerifierHaveNotDrifted(t *testing.T) {
	for _, name := range []string{"bundle.go", "certs.go"} {
		other, err := os.ReadFile(filepath.Clean("../../../node/backend/internal/trust/" + name))
		if err != nil {
			t.Skipf("node copy unavailable: %v", err)
		}
		mine, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		normalized := strings.NewReplacer(
			"package trust", "package pki",
			"github.com/jfxdev/jolt/backend/internal/signedauth", "github.com/jfxdev/jolt/control/internal/signedauth",
		).Replace(string(other))
		if string(mine) != normalized {
			t.Fatalf("control/internal/pki/%s has drifted from node/backend/internal/trust/%s;\napply the change to both copies", name, name)
		}
	}
}
