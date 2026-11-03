package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
	"go.yaml.in/yaml/v3"
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

func TestUploadReauthorizationIsAtomicAndRejectsStaleBinding(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	legacy := entities.UploadSession{ID: "legacy", MountID: "files", Destination: "file.txt"}
	if err := s.CreateUploadSession(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	initial := signedauth.UploadReauthorizationRequestID(legacy.ID, "", 0)
	if err := s.ReauthorizeUploadSession(ctx, legacy.ID, "actor", "credential-1", initial); err != nil {
		t.Fatal(err)
	}
	if err := s.ReauthorizeUploadSession(ctx, legacy.ID, "actor", "credential-2", initial); !errors.Is(err, ErrInUse) {
		t.Fatalf("stale binding accepted: %v", err)
	}
	current := signedauth.UploadReauthorizationRequestID(legacy.ID, "credential-1", 1)
	if err := s.ReauthorizeUploadSession(ctx, legacy.ID, "other", "credential-2", current); !errors.Is(err, ErrInUse) {
		t.Fatalf("different actor accepted: %v", err)
	}
	if err := s.ReauthorizeUploadSession(ctx, legacy.ID, "actor", "credential-2", current); err != nil {
		t.Fatal(err)
	}
	if err := s.ReauthorizeUploadSession(ctx, legacy.ID, "actor", "credential-1", current); !errors.Is(err, ErrInUse) {
		t.Fatalf("reauthorization replay accepted: %v", err)
	}
	if err := s.ReauthorizeUploadSession(ctx, legacy.ID, "actor", "credential-1", signedauth.UploadReauthorizationRequestID(legacy.ID, "credential-2", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReauthorizeUploadSession(ctx, legacy.ID, "actor", "credential-2", current); !errors.Is(err, ErrInUse) {
		t.Fatalf("old revision accepted after credential cycle: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetUploadSession(ctx, legacy.ID)
	if err != nil || got.AuthorizationActorID != "actor" || got.AuthorizationCredentialID != "credential-1" || got.AuthorizationRevision != 3 || s.envelopeVersion != 3 {
		t.Fatalf("binding not recovered: %+v version=%d err=%v", got, s.envelopeVersion, err)
	}
}

func TestUploadBindingSecurityVersionUpgradeSurvivesFailure(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, dir := openTest(t)
			ctx := context.Background()
			legacy := entities.UploadSession{ID: "legacy", MountID: "files", Destination: "legacy.txt"}
			if err := s.CreateUploadSession(ctx, legacy); err != nil {
				t.Fatal(err)
			}
			s.fault = func(at string) error {
				if at == point {
					return errors.New("injected failure")
				}
				return nil
			}
			bound := entities.UploadSession{ID: "bound", MountID: "files", Destination: "bound.txt", AuthorizationActorID: "actor", AuthorizationCredentialID: "credential"}
			if err := s.CreateUploadSession(ctx, bound); !errors.Is(err, contracts.ErrStateUnavailable) {
				t.Fatalf("upgrade failure = %v", err)
			}
			if _, err := s.GetUploadSession(ctx, legacy.ID); !errors.Is(err, contracts.ErrStateUnavailable) {
				t.Fatalf("store did not stop after uncertain upgrade: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "store.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var header envelope
			if err := yaml.Unmarshal(raw, &header); err != nil {
				t.Fatal(err)
			}
			want := 1
			if point == "after_rename" || point == "after_directory_sync" {
				want = 2
			}
			if header.Version != want {
				t.Fatalf("header version=%d want=%d", header.Version, want)
			}
			reopened, err := Open(dir, testKey)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if _, err := reopened.GetUploadSession(ctx, legacy.ID); err != nil {
				t.Fatalf("legacy data unavailable: %v", err)
			}
			if _, err := reopened.GetUploadSession(ctx, bound.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("binding persisted before version upgrade completed: %v", err)
			}
		})
	}
}

func TestVersionTwoUploadRecoveryAfterInterruptedTransaction(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, dir := openTest(t)
			ctx := context.Background()
			bound := entities.UploadSession{ID: "bound", MountID: "files", Destination: "file.txt", State: "open", AuthorizationActorID: "actor", AuthorizationCredentialID: "credential"}
			if err := s.CreateUploadSession(ctx, bound); err != nil {
				t.Fatal(err)
			}
			s.fault = func(at string) error {
				if at == point {
					return errors.New("injected failure")
				}
				return nil
			}
			bound.State = "publishing"
			if err := s.UpdateUploadSession(ctx, bound); !errors.Is(err, contracts.ErrStateUnavailable) {
				t.Fatalf("interrupted update = %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(dir, testKey)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			got, err := reopened.GetUploadSession(ctx, bound.ID)
			want := "open"
			if point == "after_rename" || point == "after_directory_sync" {
				want = "publishing"
			}
			if err != nil || got.State != want || got.AuthorizationActorID != "actor" || got.AuthorizationCredentialID != "credential" || reopened.envelopeVersion != 2 {
				t.Fatalf("recovered session=%+v version=%d err=%v", got, reopened.envelopeVersion, err)
			}
		})
	}
}

func TestReauthorizationVersionUpgradeSurvivesFailure(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, dir := openTest(t)
			ctx := context.Background()
			bound := entities.UploadSession{ID: "bound", MountID: "files", Destination: "file.txt", AuthorizationActorID: "actor", AuthorizationCredentialID: "old"}
			if err := s.CreateUploadSession(ctx, bound); err != nil {
				t.Fatal(err)
			}
			s.fault = func(at string) error {
				if at == point {
					return errors.New("injected failure")
				}
				return nil
			}
			if err := s.ReauthorizeUploadSession(ctx, bound.ID, "actor", "new", signedauth.UploadReauthorizationRequestID(bound.ID, "old", 0)); !errors.Is(err, contracts.ErrStateUnavailable) {
				t.Fatalf("interrupted upgrade = %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err := Open(dir, testKey)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, err := s.GetUploadSession(ctx, bound.ID)
			wantVersion := 2
			if point == "after_rename" || point == "after_directory_sync" {
				wantVersion = 3
			}
			if err != nil || got.AuthorizationCredentialID != "old" || got.AuthorizationRevision != 0 || s.envelopeVersion != wantVersion {
				t.Fatalf("recovered=%+v version=%d err=%v", got, s.envelopeVersion, err)
			}
		})
	}
}

func TestUploadBindingUpgradesHeaderAndKeepsLegacyRecords(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	legacy := entities.UploadSession{ID: "legacy", MountID: "files", Destination: "old.txt"}
	bound := entities.UploadSession{ID: "bound", MountID: "files", Destination: "new.txt", AuthorizationActorID: "actor", AuthorizationCredentialID: "credential"}
	if err := s.CreateUploadSession(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if s.envelopeVersion != 1 {
		t.Fatal("legacy session unnecessarily upgraded state")
	}
	if err := s.CreateUploadSession(ctx, bound); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var header envelope
	if err := yaml.Unmarshal(raw, &header); err != nil || header.Version != 2 {
		t.Fatalf("header not upgraded: %+v %v", header, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenExisting(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, expected := range []entities.UploadSession{legacy, bound} {
		got, err := s.GetUploadSession(ctx, expected.ID)
		if err != nil || got.Destination != expected.Destination || got.AuthorizationActorID != expected.AuthorizationActorID || got.AuthorizationCredentialID != expected.AuthorizationCredentialID {
			t.Fatalf("mixed-version session %s: %+v %v", expected.ID, got, err)
		}
	}
}

func TestStateEnvelopeVersionIsAuthenticated(t *testing.T) {
	s, dir := openTest(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	headerPath := filepath.Join(dir, "store.yaml")
	raw, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatal(err)
	}
	var header envelope
	if err := yaml.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	header.Version = 2
	raw, err = yaml.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(headerPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir, testKey); err == nil {
		reopened.Close()
		t.Fatal("unauthenticated version change accepted")
	}
}

func TestPreviousStateReaderRejectsBoundUpload(t *testing.T) {
	checker := os.Getenv("JOLT_PREVIOUS_STATE_CHECKER")
	if checker == "" {
		t.Skip("set JOLT_PREVIOUS_STATE_CHECKER to a state reader built from the previous version")
	}
	s, dir := openTest(t)
	ctx := context.Background()
	if err := s.CreateUploadSession(ctx, entities.UploadSession{ID: "legacy", MountID: "files", Destination: "old.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, dir).CombinedOutput(); err != nil {
		t.Fatalf("previous reader rejected legacy state: %v %s", err, out)
	}
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUploadSession(ctx, entities.UploadSession{ID: "bound", MountID: "files", Destination: "new.txt", AuthorizationActorID: "actor", AuthorizationCredentialID: "credential"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, dir).CombinedOutput(); err == nil || !strings.Contains(string(out), "state envelope identity mismatch") {
		t.Fatalf("previous reader did not reject version 2: %v %s", err, out)
	}
}

func TestVersionTwoReaderRejectsReauthorizationRevision(t *testing.T) {
	checker := os.Getenv("JOLT_VERSION2_STATE_CHECKER")
	if checker == "" {
		t.Skip("set JOLT_VERSION2_STATE_CHECKER to a reader built before upload reauthorization")
	}
	s, dir := openTest(t)
	ctx := context.Background()
	bound := entities.UploadSession{ID: "bound", MountID: "files", Destination: "file.txt", AuthorizationActorID: "actor", AuthorizationCredentialID: "old"}
	if err := s.CreateUploadSession(ctx, bound); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, dir).CombinedOutput(); err != nil {
		t.Fatalf("version 2 reader rejected version 2 state: %v %s", err, out)
	}
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReauthorizeUploadSession(ctx, bound.ID, "actor", "new", signedauth.UploadReauthorizationRequestID(bound.ID, "old", 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, dir).CombinedOutput(); err == nil || !strings.Contains(string(out), "state envelope identity mismatch") {
		t.Fatalf("version 2 reader did not reject version 3 state: %v %s", err, out)
	}
}
