package httpapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

func TestTransferGrantExclusionsAreReflectedInSelection(t *testing.T) {
	grant := nodeTransferGrant{Enabled: true, PeerNodeID: "peer", MountID: "media", Path: ".", Direction: "send", Exclude: []string{"*.pem", "private"}}
	grant.Permissions.Read = true
	if !sourceGrantAllows(grant, "peer", "media", []string{"public/report.txt"}, "copy") {
		t.Fatal("allowed source was rejected")
	}
	for _, name := range []string{"public/key.PEM", "private/file.txt"} {
		if sourceGrantAllows(grant, "peer", "media", []string{name}, "copy") {
			t.Fatalf("excluded source %q was accepted", name)
		}
	}
	grant.Exclude = []string{"[invalid"}
	if sourceGrantAllows(grant, "peer", "media", []string{"public"}, "copy") {
		t.Fatal("invalid exclusion was ignored")
	}
	grant.Direction = "receive"
	grant.Permissions.Write = true
	if destinationGrantAllows(grant, "peer") {
		t.Fatal("invalid receiving exclusion was advertised")
	}
	grant.Exclude = []string{"*.pem"}
	if !destinationGrantAllows(grant, "peer") || grantAllowsPath(grant, "folder/key.PEM") || !grantAllowsPath(grant, "folder/report.txt") {
		t.Fatal("receiving exclusions were not applied to destination paths")
	}
	if got := grantsSupportedByNode([]nodeTransferGrant{grant}, nil, "grant_exclude_receive_v1"); len(got) != 0 {
		t.Fatal("an incompatible node was allowed to enforce receiving exclusions")
	}
	if got := grantsSupportedByNode([]nodeTransferGrant{grant}, []string{"grant_exclude_receive_v1"}, "grant_exclude_receive_v1"); len(got) != 1 {
		t.Fatal("a compatible node was rejected")
	}
}

func TestDirectTransferRequiresGrantExclusionCapabilities(t *testing.T) {
	sourceExclude, destinationExclude := false, false
	sourceCapability, destinationCapability, metadataUnavailable := true, true, false
	forwarded := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, status := `{}`, http.StatusOK
		source := r.URL.Host == "source.test"
		switch r.URL.Path {
		case "/api/v1/grants":
			if source {
				exclude := `[]`
				if sourceExclude {
					exclude = `["*.pem"]`
				}
				body = `{"items":[{"grant_id":"src","peer_node_id":"destination","mount_id":"media","path":".","direction":"send","enabled":true,"permissions":{"read":true},"exclude":` + exclude + `}]}`
			} else {
				exclude := `[]`
				if destinationExclude {
					exclude = `["*.secret"]`
				}
				body = `{"items":[{"grant_id":"dst","peer_node_id":"source","mount_id":"incoming","path":".","direction":"receive","enabled":true,"permissions":{"write":true},"exclude":` + exclude + `}]}`
			}
		case "/api/v1/node":
			if metadataUnavailable {
				status = http.StatusServiceUnavailable
				break
			}
			id, caps := "destination", `[]`
			if source {
				id = "source"
				if sourceCapability {
					caps = `["grant_exclude_send_v1"]`
				}
			} else if destinationCapability {
				caps = `["grant_exclude_receive_v1"]`
			}
			body = fmt.Sprintf(`{"node_id":%q,"fingerprint":"FP","capabilities":%s}`, id, caps)
		case "/api/v1/transfers/pull":
			forwarded++
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	handler, storage, session := testUserHandlerWithClient(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true}, client)
	now := time.Now().UTC()
	token, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"source", "destination"} {
		if err := storage.SaveNode(context.Background(), store.Node{ID: id, Name: id, Endpoint: "http://" + id + ".test", TokenEncrypted: token, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name                                                                                    string
		sourceExclude, destinationExclude, sourceCapability, destinationCapability, unavailable bool
		sourcePath, destinationPath                                                             string
		want                                                                                    int
	}{
		{"legacy grants need no new capability", false, false, false, false, false, "file.txt", "out.txt", 200},
		{"unsupported source", true, false, false, true, false, "file.txt", "out.txt", 409},
		{"unsupported destination", false, true, true, false, false, "file.txt", "out.txt", 409},
		{"unavailable metadata", true, false, true, true, true, "file.txt", "out.txt", 502},
		{"excluded source", true, false, true, true, false, "folder/key.PEM", "out.txt", 400},
		{"excluded destination", false, true, true, true, false, "file.txt", "folder/key.SECRET", 400},
		{"supported nodes", true, true, true, true, false, "file.txt", "out.txt", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourceExclude, destinationExclude = tc.sourceExclude, tc.destinationExclude
			sourceCapability, destinationCapability, metadataUnavailable = tc.sourceCapability, tc.destinationCapability, tc.unavailable
			body := fmt.Sprintf(`{"peer_node_id":"source","source_grant_id":"src","destination_grant_id":"dst","source_path":%q,"destination_path":%q}`, tc.sourcePath, tc.destinationPath)
			before := forwarded
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers/pull", session, []byte(body)))
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			if tc.want != 200 && forwarded != before {
				t.Fatal("rejected transfer reached the destination node")
			}
			if tc.want == 409 && !strings.Contains(w.Body.String(), "node_upgrade_required") {
				t.Fatalf("missing upgrade guidance: %s", w.Body.String())
			}
		})
	}
}
