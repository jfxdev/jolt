package signedauth

import (
	"testing"
	"time"
)

func TestVerifyLocalUploadBindsPersistedSession(t *testing.T) {
	claims, key, keys := fixture()
	claims.Binding.SourceNodeID, claims.Binding.SourceMountID, claims.Binding.SourceRoot, claims.Binding.SourceGrantID = "", "", "", ""
	claims.Binding.DestinationNodeID, claims.Binding.DestinationMountID = "node", "mount"
	claims.Binding.DestinationRoot, claims.Binding.DestinationGrantID, claims.Binding.PlanID = "folder/file.txt", "", "upload-1"
	now := time.Unix(claims.IssuedAt, 0)
	for _, operation := range []string{"upload_chunk", "upload_complete", "upload_abort"} {
		claims.Binding.Operation = operation
		token, err := Sign(claims, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyLocalUpload(token, keys, "user-1", "credential-1", "node", operation, "mount", "folder/file.txt", "upload-1", now); err != nil {
			t.Fatalf("valid %s: %v", operation, err)
		}
		for _, identity := range [][2]string{{"other", "credential-1"}, {"user-1", "other"}, {"", "credential-1"}, {"user-1", ""}} {
			if _, _, err := VerifyLocalUpload(token, keys, identity[0], identity[1], "node", operation, "mount", "folder/file.txt", "upload-1", now); err == nil {
				t.Fatalf("accepted different actor or credential: %v", identity)
			}
		}
		otherOperation := "upload_chunk"
		if operation == otherOperation {
			otherOperation = "upload_complete"
		}
		for _, tc := range []struct{ node, op, mount, dest, session string }{
			{"other", operation, "mount", "folder/file.txt", "upload-1"},
			{"node", otherOperation, "mount", "folder/file.txt", "upload-1"},
			{"node", "upload_other", "mount", "folder/file.txt", "upload-1"},
			{"node", operation, "other", "folder/file.txt", "upload-1"},
			{"node", operation, "mount", "folder/other.txt", "upload-1"},
			{"node", operation, "mount", "folder/file.txt", "upload-2"},
			{"node", operation, "mount", "folder/file.txt", ""},
		} {
			if _, _, err := VerifyLocalUpload(token, keys, "user-1", "credential-1", tc.node, tc.op, tc.mount, tc.dest, tc.session, now); err == nil {
				t.Fatalf("accepted different session: %+v", tc)
			}
		}
		if _, _, err := VerifyLocalUpload(token, keys, "user-1", "credential-1", "node", operation, "mount", "folder/file.txt", "upload-1", now.Add(MaxLifetime)); err == nil {
			t.Fatal("accepted expired upload authorization")
		}
	}
	claims.Binding.DestinationGrantID = "grant"
	claims.Binding.Operation = "upload_complete"
	token, err := Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyLocalUpload(token, keys, "user-1", "credential-1", "node", "upload_complete", "mount", "folder/file.txt", "upload-1", now); err == nil {
		t.Fatal("accepted transfer grant for local upload")
	}
	claims.Binding.DestinationGrantID = ""
	claims.Binding.SourceNodeID, claims.Binding.SourceMountID, claims.Binding.SourceRoot = "other", "mount", "file.txt"
	token, err = Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyLocalUpload(token, keys, "user-1", "credential-1", "node", "upload_complete", "mount", "folder/file.txt", "upload-1", now); err == nil {
		t.Fatal("accepted source node for local upload")
	}
}

func TestVerifyUploadAdmissionBindsDestination(t *testing.T) {
	claims, key, keys := fixture()
	body := []byte(`{"path":"folder/file.txt","overwrite":false}`)
	claims.Binding.SourceNodeID, claims.Binding.SourceMountID, claims.Binding.SourceRoot, claims.Binding.SourceGrantID = "", "", "", ""
	claims.Binding.DestinationNodeID, claims.Binding.DestinationMountID = "node", "mount"
	claims.Binding.DestinationRoot, claims.Binding.DestinationGrantID, claims.Binding.PlanID = "folder/file.txt", "", UploadAdmissionBodyID(body)
	claims.Binding.Operation = "upload_create"
	token, err := Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(claims.IssuedAt, 0)
	if _, _, err := VerifyUploadAdmission(token, keys, "node", "mount", "folder/file.txt", body, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range [][3]string{{"other", "mount", "folder/file.txt"}, {"node", "other", "folder/file.txt"}, {"node", "mount", "other.txt"}, {"node", "mount", "."}} {
		if _, _, err := VerifyUploadAdmission(token, keys, tc[0], tc[1], tc[2], body, now); err == nil {
			t.Fatalf("accepted different admission target: %v", tc)
		}
	}
	if _, _, err := VerifyUploadAdmission(token, keys, "node", "mount", "folder/file.txt", []byte(`{"path":"folder/file.txt","overwrite":true}`), now); err == nil {
		t.Fatal("accepted changed upload admission body")
	}
	claims.Binding.Operation, claims.Binding.PlanID = "upload_complete", "upload-1"
	token, err = Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyUploadAdmission(token, keys, "node", "mount", "folder/file.txt", body, now); err == nil {
		t.Fatal("accepted completion token as admission")
	}
}

func TestVerifyUploadReauthorizationRequiresCurrentBinding(t *testing.T) {
	claims, key, keys := fixture()
	claims.Binding.SourceNodeID, claims.Binding.SourceMountID, claims.Binding.SourceRoot, claims.Binding.SourceGrantID = "", "", "", ""
	claims.Binding.DestinationNodeID, claims.Binding.DestinationMountID, claims.Binding.DestinationRoot, claims.Binding.DestinationGrantID = "node", "mount", "file.txt", ""
	claims.Binding.Operation, claims.Binding.PlanID = "upload_reauthorize", "upload-1"
	claims.Binding.RequestID = UploadReauthorizationRequestID("upload-1", "old-credential", 3)
	token, err := Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(claims.IssuedAt, 0)
	if _, _, err := VerifyUploadReauthorization(token, keys, "user-1", "old-credential", "node", "mount", "file.txt", "upload-1", 3, now); err != nil {
		t.Fatal(err)
	}
	for _, identity := range [][2]string{{"other", "old-credential"}, {"user-1", "new-credential"}, {"", "old-credential"}, {"user-1", ""}} {
		if _, _, err := VerifyUploadReauthorization(token, keys, identity[0], identity[1], "node", "mount", "file.txt", "upload-1", 3, now); err == nil {
			t.Fatalf("accepted stale or different binding: %v", identity)
		}
	}
	if _, _, err := VerifyUploadReauthorization(token, keys, "user-1", "old-credential", "node", "mount", "file.txt", "upload-1", 4, now); err == nil {
		t.Fatal("accepted a previous authorization revision")
	}
}
