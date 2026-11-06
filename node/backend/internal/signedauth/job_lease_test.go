package signedauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJobLeaseBindingReplayAndScope(t *testing.T) {
	claims, key, keys := fixture()
	base := claims.Binding
	base.Operation, base.PlanID, base.RequestID = "transfer_move_batch", "job-123", ""
	binding, err := JobLeaseBinding(base, 1)
	if err != nil {
		t.Fatal(err)
	}
	if binding.RequestID != "job-62a8c24990a839484464851b2a8b4f04d883ed3dc432bc7f341e16e4604edc60" {
		t.Fatalf("job lease vector=%q", binding.RequestID)
	}
	claims.Binding = binding
	token, err := Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(claims.IssuedAt, 0)
	candidate, err := VerifiedJobLeaseBinding(token, keys, "source", now)
	if err != nil || candidate != base {
		t.Fatalf("verified candidate=%+v err=%v", candidate, err)
	}
	if _, err := VerifiedJobLeaseBinding(token, keys, "other", now); err == nil {
		t.Fatal("candidate accepted for wrong node")
	}
	if _, err := VerifiedJobLeaseBinding(token, map[string]ed25519.PublicKey{}, "source", now); err == nil {
		t.Fatal("candidate accepted without key")
	}
	for _, node := range []string{"source", "destination"} {
		if _, _, err := VerifyJobLease(token, keys, base, node, 1, now); err != nil {
			t.Fatalf("%s: %v", node, err)
		}
	}
	mutations := []func(*Binding){
		func(b *Binding) { b.ActorID = "other" }, func(b *Binding) { b.CredentialID = "other" },
		func(b *Binding) { b.SourceNodeID = "other" }, func(b *Binding) { b.SourceGrantID = "other" },
		func(b *Binding) { b.SourceMountID = "other" }, func(b *Binding) { b.SourceRoot = "other" },
		func(b *Binding) { b.DestinationNodeID = "other" }, func(b *Binding) { b.DestinationGrantID = "other" },
		func(b *Binding) { b.DestinationMountID = "other" }, func(b *Binding) { b.DestinationRoot = "other" },
		func(b *Binding) { b.PlanID = "other" }, func(b *Binding) { b.Operation = "transfer_pull" },
	}
	for i, mutate := range mutations {
		changed := base
		mutate(&changed)
		if _, _, err := VerifyJobLease(token, keys, changed, "source", 1, now); err == nil {
			t.Fatalf("binding %d accepted", i)
		}
	}
	if _, _, err := VerifyJobLease(token, keys, base, "source", 2, now); err == nil {
		t.Fatal("old revision replayed")
	}
	if _, _, err := VerifyJobLease(token, keys, base, "other", 1, now); err == nil {
		t.Fatal("wrong node accepted")
	}
	if _, _, err := VerifyJobLease(token, keys, base, "source", 1, time.Unix(claims.ExpiresAt, 0)); err == nil {
		t.Fatal("expired lease accepted")
	}
	if _, _, err := VerifyJobLease(token, map[string]ed25519.PublicKey{}, base, "source", 1, now); err == nil {
		t.Fatal("unknown key accepted")
	}
	sum := sha256.Sum256([]byte(token))
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var golden []byte
	for {
		golden, err = os.ReadFile(filepath.Join(dir, "testdata", "job-lease-sha256.txt"))
		if err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("shared job lease fixture not found")
		}
		dir = parent
	}
	if got := fmt.Sprintf("%x", sum); got != strings.TrimSpace(string(golden)) {
		t.Fatalf("job lease golden=%s", got)
	}
}

func TestJobLeaseRejectsInvalidTopology(t *testing.T) {
	claims, _, _ := fixture()
	base := claims.Binding
	base.Operation, base.PlanID, base.RequestID = "transfer_pull", "job-123", ""
	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.SourceGrantID = "" }, func(b *Binding) { b.DestinationGrantID = "" },
		func(b *Binding) { b.DestinationNodeID = b.SourceNodeID }, func(b *Binding) { b.PlanID = "" },
		func(b *Binding) { b.RequestID = "attacker" }, func(b *Binding) { b.Operation = "upload_simple" },
		func(b *Binding) { b.SourceRoot = "../escape" }, func(b *Binding) { b.SourceGrantID = "grant/invalid" },
	} {
		changed := base
		mutate(&changed)
		if _, err := JobLeaseBinding(changed, 1); err == nil {
			t.Fatalf("invalid topology accepted: %+v", changed)
		}
	}
	if _, err := JobLeaseBinding(base, 0); err == nil {
		t.Fatal("zero revision accepted")
	}
	local := Binding{ActorID: "actor", CredentialID: "credential", Operation: "move_local", SourceNodeID: "node", SourceMountID: "mount", SourceRoot: "from", DestinationNodeID: "node", DestinationMountID: "mount", DestinationRoot: "to", PlanID: "job"}
	if _, err := JobLeaseBinding(local, 1); err != nil {
		t.Fatal(err)
	}
	local.DestinationMountID = "other"
	if _, err := JobLeaseBinding(local, 1); err == nil {
		t.Fatal("cross-mount local job accepted")
	}
	deleteBinding := Binding{ActorID: "actor", CredentialID: "credential", Operation: "delete", SourceNodeID: "node", SourceMountID: "mount", SourceRoot: "tree", PlanID: "job"}
	if _, err := JobLeaseBinding(deleteBinding, 1); err != nil {
		t.Fatal(err)
	}
	deleteBinding.SourceGrantID = "grant"
	if _, err := JobLeaseBinding(deleteBinding, 1); err == nil {
		t.Fatal("grant on local delete accepted")
	}
}
