package jobs

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func TestCreateAwaitingSignedAuthorization(t *testing.T) {
	service, _, mountID := testService(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	service.now = func() time.Time { return now }
	request := CreateRequest{Type: "copy_local", MountID: mountID, SourcePath: "source", Destination: "destination"}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	options := signedauth.JobOptions{ConflictPolicy: "fail", SourceChangePolicy: "fail", MaxParallelFiles: 2, MaxParallelChunks: 1, MaxAttempts: 3}
	prepared, digest, err := service.PrepareSignedLocalCopy(ctx, request)
	if err != nil || prepared != options || digest != signedauth.JobOptionsDigest(options) {
		t.Fatalf("prepared=%+v digest=%q err=%v", prepared, digest, err)
	}
	invalidPath := request
	invalidPath.SourcePath = "../escape"
	if _, _, err := service.PrepareSignedLocalCopy(ctx, invalidPath); err == nil {
		t.Fatal("noncanonical path prepared")
	}
	binding := signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: request.Type, SourceNodeID: "node", SourceMountID: mountID, SourceRoot: request.SourcePath, DestinationNodeID: "node", DestinationMountID: mountID, DestinationRoot: request.Destination, PlanID: "job", JobOptionsDigest: signedauth.JobOptionsDigest(options)}
	sign := func(b signedauth.Binding, issued time.Time) string {
		t.Helper()
		b, err := signedauth.JobLeaseBinding(b, 1)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := signedauth.Sign(signedauth.Claims{Version: 1, KeyID: "key", Binding: b, IssuedAt: issued.Unix(), ExpiresAt: issued.Add(30 * time.Second).Unix(), Context: json.RawMessage(`{"version":1,"rules":[]}`)}, key)
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	envelope := sign(binding, now)
	for _, tc := range []struct {
		name                     string
		request                  CreateRequest
		node, token, idempotency string
	}{
		{"tampered", request, "node", envelope + "x", "key"},
		{"wrong node", request, "other", envelope, "key"},
		{"expired", request, "node", sign(binding, now.Add(-time.Minute)), "key"},
		{"missing key", request, "node", envelope, ""},
		{"changed source", CreateRequest{Type: "copy_local", MountID: mountID, SourcePath: "other", Destination: "destination"}, "node", envelope, "key"},
		{"changed overwrite", CreateRequest{Type: "copy_local", MountID: mountID, SourcePath: "source", Destination: "destination", Overwrite: true}, "node", envelope, "key"},
		{"delete excluded", CreateRequest{Type: "delete", MountID: mountID, SourcePath: "source", Recursive: true}, "node", envelope, "key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := service.CreateAwaitingSignedAuthorization(ctx, tc.request, tc.node, tc.token, tc.idempotency, keys); err == nil {
				t.Fatal("invalid creation accepted")
			}
			if _, err := service.store.GetJob(ctx, "job"); err == nil {
				t.Fatal("invalid creation persisted a job")
			}
		})
	}
	job, repeated, err := service.CreateAwaitingSignedAuthorization(ctx, request, "node", envelope, "key", keys)
	if err != nil || repeated || job.ID != "job" || job.State != "waiting_validation" || !job.RequiresSignedAuth || job.SignedAuthActorID != "actor" || job.SignedAuthCredentialID != "credential" {
		t.Fatalf("job=%+v repeated=%v err=%v", job, repeated, err)
	}
	if job.ConflictPolicy != "fail" || job.SourceChangePolicy != "fail" || job.MaxAttempts != 3 || job.MaxParallelFiles != 2 || job.MaxParallelChunks != 1 {
		t.Fatalf("job options were not normalized: %+v", job)
	}
	if got, repeated, err := service.CreateAwaitingSignedAuthorization(ctx, request, "node", envelope, "key", keys); err != nil || !repeated || got.ID != job.ID {
		t.Fatalf("retry=%+v repeated=%v err=%v", got, repeated, err)
	}
	changed := binding
	changed.ActorID = "other"
	if _, _, err := service.CreateAwaitingSignedAuthorization(ctx, request, "node", sign(changed, now), "key", keys); !errors.Is(err, contracts.ErrIdempotencyConflict) {
		t.Fatalf("other actor reused idempotency key: %v", err)
	}
	if _, err := service.Resume(ctx, job.ID); err == nil {
		t.Fatal("job resumed without execution integration")
	}
	if _, err := service.store.ClaimNextJob(ctx, now); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("job claimed without execution integration: %v", err)
	}
}
