package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadInspectionPreservesDestinationAndRemovesRejectedPartials(t *testing.T) {
	for _, resumable := range []bool{false, true} {
		t.Run(map[bool]string{false: "simple", true: "resumable"}[resumable], func(t *testing.T) {
			s, mountID, root := newTestService(t, "read_write")
			s.ConfigureUploadInspection(UploadInspection{Enabled: true, BlockExecutables: true, AllowedMediaTypes: []string{"text/plain"}})
			destination := filepath.Join(root, "file.txt")
			if err := os.WriteFile(destination, []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			payload := "\x7fELFpretend-executable"
			var err error
			if resumable {
				_, err = s.AppendUpload(context.Background(), mountID, "file.txt", "upload", 0, int64(len(payload)), strings.NewReader(payload))
				if err == nil {
					_, _, err = s.CompleteUpload(context.Background(), mountID, "file.txt", "upload", int64(len(payload)), "", true)
				}
			} else {
				_, err = s.Upload(context.Background(), mountID, "file.txt", strings.NewReader(payload), true)
			}
			if !errors.Is(err, ErrUploadContentRejected) {
				t.Fatalf("rejection = %v", err)
			}
			if resumable {
				// The session layer records rejection before removing the partial.
				if err := s.AbortUpload(context.Background(), mountID, "file.txt", "upload"); err != nil {
					t.Fatal(err)
				}
			}
			content, err := os.ReadFile(destination)
			if err != nil || string(content) != "existing" {
				t.Fatalf("destination changed: %q %v", content, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != "file.txt" {
				t.Fatalf("rejected partial remains: %+v %v", entries, err)
			}
			if _, err := s.Upload(context.Background(), mountID, "allowed.txt", strings.NewReader("ordinary text"), false); err != nil {
				t.Fatalf("text rejected: %v", err)
			}
		})
	}
}

func TestUploadInspectionRejectsSignaturesAndUnexpectedMedia(t *testing.T) {
	s, mountID, _ := newTestService(t, "read_write")
	s.ConfigureUploadInspection(UploadInspection{Enabled: true, BlockExecutables: true, AllowedMediaTypes: []string{"text/plain"}})
	for _, data := range []string{"MZsynthetic", "#! /bin/sh\n", "\x00asmxxxx", "\xcf\xfa\xed\xfe", "%PDF-1.7\n"} {
		if _, err := s.Upload(context.Background(), mountID, "upload.txt", strings.NewReader(data), false); !errors.Is(err, ErrUploadContentRejected) {
			t.Fatalf("content %q: %v", data, err)
		}
	}
	s.ConfigureUploadInspection(UploadInspection{})
	if _, err := s.Upload(context.Background(), mountID, "allowed.bin", strings.NewReader("MZsynthetic"), false); err != nil {
		t.Fatalf("disabled inspection changed behavior: %v", err)
	}
}
