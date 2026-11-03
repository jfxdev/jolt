package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

func TestUploadAuthorizationIdentityIsDurableAndImmutable(t *testing.T) {
	s, dir := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	bound := entities.UploadSession{ID: "bound", MountID: "files", Destination: "file.txt", Size: 5, Overwrite: true,
		AuthorizationActorID: "secret-actor-marker", AuthorizationCredentialID: "secret-credential-marker", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	for _, incomplete := range []entities.UploadSession{
		{ID: "bad-a", AuthorizationActorID: "actor"},
		{ID: "bad-c", AuthorizationCredentialID: "credential"},
		{ID: "bad-id", AuthorizationActorID: "bad/id", AuthorizationCredentialID: "credential"},
	} {
		if err := s.CreateUploadSession(ctx, incomplete); err == nil {
			t.Fatal("invalid authorization binding accepted")
		}
	}
	if err := s.CreateUploadSession(ctx, bound); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*entities.UploadSession){
		func(v *entities.UploadSession) { v.AuthorizationActorID = "other" },
		func(v *entities.UploadSession) { v.AuthorizationCredentialID = "other" },
		func(v *entities.UploadSession) { v.AuthorizationActorID, v.AuthorizationCredentialID = "", "" },
		func(v *entities.UploadSession) { v.Overwrite = false },
	} {
		changed := bound
		mutate(&changed)
		if err := s.UpdateUploadSession(ctx, changed); !errors.Is(err, ErrInUse) {
			t.Fatalf("immutable identity change accepted: %v", err)
		}
	}
	legacy := entities.UploadSession{ID: "legacy", MountID: "files", Destination: "legacy.txt", CreatedAt: now}
	if err := s.CreateUploadSession(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	legacy.AuthorizationActorID, legacy.AuthorizationCredentialID = "actor", "credential"
	if err := s.UpdateUploadSession(ctx, legacy); !errors.Is(err, ErrInUse) {
		t.Fatalf("legacy session silently bound: %v", err)
	}
	if err := s.TouchUploadSession(ctx, bound.ID, now.Add(time.Minute), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	recovered, err := s.GetUploadSession(ctx, bound.ID)
	if err != nil || recovered.AuthorizationActorID != bound.AuthorizationActorID || recovered.AuthorizationCredentialID != bound.AuthorizationCredentialID || !recovered.Overwrite || !recovered.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("binding not recovered: %+v %v", recovered, err)
	}
	encoded, err := json.Marshal(recovered)
	if err != nil || strings.Contains(string(encoded), "secret-actor-marker") || strings.Contains(string(encoded), "secret-credential-marker") {
		t.Fatalf("binding exposed by JSON: %s %v", encoded, err)
	}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "secret-actor-marker") || strings.Contains(string(data), "secret-credential-marker") {
			t.Errorf("authorization identity exposed in %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
