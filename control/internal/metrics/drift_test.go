package metrics

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMetricsPackageMatchesTheNodeCopy guards the one real risk of keeping two
// copies of this package: a fix landing in one and not the other. The node and
// the Control Tower are separate Go modules, so neither can import the other's
// internal package, and a shared module would have to be published and
// versioned for two files. Keeping byte-identical copies plus this check is
// the cheaper trade, as long as drift is loud.
//
// If the copies must genuinely differ, extract the shared logic into its own
// module rather than silencing this test.
func TestMetricsPackageMatchesTheNodeCopy(t *testing.T) {
	const relative = "../../../node/backend/internal/infra/metrics/metrics.go"
	other, err := os.ReadFile(filepath.Clean(relative))
	if err != nil {
		// Running outside a full repository checkout is not a failure.
		t.Skipf("node copy unavailable: %v", err)
	}
	mine, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(mine) != string(other) {
		t.Fatalf("control/internal/metrics/metrics.go has drifted from %s;\n"+
			"apply the change to both copies, or extract a shared module", relative)
	}
}
