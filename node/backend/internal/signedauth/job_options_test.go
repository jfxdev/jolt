package signedauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJobOptionsSharedVectorsAndMutations(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var golden []byte
	for {
		golden, err = os.ReadFile(filepath.Join(dir, "testdata", "job-options-sha256.txt"))
		if err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("shared job options fixture not found")
		}
		dir = parent
	}
	lines := strings.Split(strings.TrimSpace(string(golden)), "\n")
	options := JobOptions{Overwrite: true, Recursive: true, ConflictPolicy: "overwrite", SourceChangePolicy: "fail", VerifyChecksum: true, BandwidthLimit: 1048576, MaxParallelFiles: 4, MaxParallelChunks: 2, MaxAttempts: 3}
	if len(lines) != 2 || JobOptionsDigest(JobOptions{}) != lines[0] || JobOptionsDigest(options) != lines[1] {
		t.Fatalf("vectors zero=%s options=%s", JobOptionsDigest(JobOptions{}), JobOptionsDigest(options))
	}
	for _, mutate := range []func(*JobOptions){func(o *JobOptions) { o.Overwrite = false }, func(o *JobOptions) { o.Recursive = false }, func(o *JobOptions) { o.ConflictPolicy = "skip" }, func(o *JobOptions) { o.SourceChangePolicy = "skip" }, func(o *JobOptions) { o.VerifyChecksum = false }, func(o *JobOptions) { o.BandwidthLimit++ }, func(o *JobOptions) { o.MaxParallelFiles++ }, func(o *JobOptions) { o.MaxParallelChunks++ }, func(o *JobOptions) { o.MaxAttempts++ }} {
		changed := options
		mutate(&changed)
		if JobOptionsDigest(changed) == lines[1] {
			t.Fatalf("option mutation did not change digest: %+v", changed)
		}
	}
	for _, invalid := range []string{"invalid", lines[1] + "=", lines[1] + "\n", strings.Repeat("a", 44)} {
		if validJobOptionsDigest(invalid) {
			t.Fatalf("invalid digest accepted %q", invalid)
		}
	}
	claims, key, keys := fixture()
	base := claims.Binding
	base.Operation, base.PlanID, base.RequestID, base.JobOptionsDigest = "transfer_move_batch", "job-123", "", lines[1]
	bound, err := JobLeaseBinding(base, 1)
	if err != nil {
		t.Fatal(err)
	}
	claims.Binding = bound
	envelope, err := Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyJobLease(envelope, keys, base, "source", 1, time.Unix(claims.IssuedAt, 0)); err != nil {
		t.Fatal(err)
	}
	base.JobOptionsDigest = lines[0]
	if _, _, err := VerifyJobLease(envelope, keys, base, "source", 1, time.Unix(claims.IssuedAt, 0)); err == nil {
		t.Fatal("different signed options accepted")
	}
	claims.Binding.Operation = "content"
	if _, err := Sign(claims, key); err == nil {
		t.Fatal("job options accepted for a non-job operation")
	}
}
