package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	"github.com/jfxdev/jolt/backend/internal/infra/metrics"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

type signedUploadRecorder struct{ *httptest.ResponseRecorder }

func (w *signedUploadRecorder) SetWriteDeadline(time.Time) error { return nil }
func (w *signedUploadRecorder) SetReadDeadline(time.Time) error  { return nil }

func TestSignedUploadEnforcesSessionAndCurrentFilter(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	files := filesystem.New(storage)
	if _, err := files.SaveMount(context.Background(), entities.Mount{ID: "m", Name: "m", LocalPath: root, Mode: "read_write", Enabled: true, Published: true}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	identity := entities.Identity{NodeID: "node"}
	cfg := config.Config{ControlTowerToken: "secret", AuthorizationKeys: map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}}
	h := New(cfg, identity, files, jobs.New(storage, files), pairing.New(storage, identity), grants.New(storage, files), slog.New(slog.NewTextHandler(io.Discard, nil)), storage, metrics.NewRegistry())
	policy := func(caps string) json.RawMessage {
		return json.RawMessage(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/node/files/mounts/m/**","capabilities":` + caps + `}]}`)
	}
	credential := "credential"
	sign := func(operation, id, actor string, context json.RawMessage) string {
		now := time.Now().Unix()
		claims := signedauth.Claims{Version: 1, KeyID: "key", IssuedAt: now, ExpiresAt: now + 20, Context: context,
			Binding: signedauth.Binding{ActorID: actor, CredentialID: credential, Operation: operation, RequestID: "request", DestinationNodeID: "node", DestinationMountID: "m", DestinationRoot: "file.txt", PlanID: id}}
		if operation == "upload_reauthorize" {
			claims.Binding.RequestID = signedauth.UploadReauthorizationRequestID(id, "credential", 0)
		}
		token, err := signedauth.Sign(claims, key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	call := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		if token != "" {
			r.Header.Set(signedAuthorizationHeader, token)
		}
		if method == http.MethodPatch {
			r.Header.Set("Content-Range", "bytes 0-2/3")
		}
		w := &signedUploadRecorder{httptest.NewRecorder()}
		h.ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	base := "/api/v1/mounts/m/files/uploads"
	body := `{"path":"file.txt","size":3,"overwrite":true}`
	admission := sign("upload_create", signedauth.UploadAdmissionBodyID([]byte(body)), "actor", policy(`["create","update"]`))
	if w := call("POST", base, strings.Replace(body, "true", "false", 1), admission); w.Code != 403 {
		t.Fatalf("altered admission: %d %s", w.Code, w.Body)
	}
	denied := json.RawMessage(`{"version":1,"rules":[{"policy_id":"allow","path":"nodes/node/files/mounts/m/**","capabilities":["create","update"]},{"policy_id":"deny","path":"nodes/node/files/mounts/m/**","capabilities":["deny","create"],"file_types":{"extensions":["txt"]}}]}`)
	if w := call("POST", base, body, sign("upload_create", signedauth.UploadAdmissionBodyID([]byte(body)), "actor", denied)); w.Code != 403 {
		t.Fatalf("typed denial: %d %s", w.Code, w.Body)
	}
	if sessions, err := storage.ListUploadSessions(context.Background(), "m"); err != nil || len(sessions) != 0 {
		t.Fatalf("denied admission mutated sessions: %v %v", sessions, err)
	}
	w := call("POST", base, body, admission)
	var session entities.UploadSession
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &session) != nil || session.ID == "" || strings.Contains(w.Body.String(), "credential") {
		t.Fatalf("admission: %d %s", w.Code, w.Body)
	}
	path := base + "/" + session.ID
	credential = "credential-new"
	renewal := sign("upload_reauthorize", session.ID, "actor", policy(`["create","update"]`))
	if w := call("POST", path+"/authorize", "{}", renewal); w.Code != 204 {
		t.Fatalf("reauthorize: %d %s", w.Code, w.Body)
	}
	if w := call("POST", path+"/authorize", "{}", renewal); w.Code != 403 {
		t.Fatalf("reauthorization replay: %d %s", w.Code, w.Body)
	}
	credential = "credential"
	if w := call("PATCH", path, "new", sign("upload_chunk", session.ID, "actor", policy(`["create","update"]`))); w.Code != 403 {
		t.Fatalf("old credential after reauthorization: %d %s", w.Code, w.Body)
	}
	credential = "credential-new"
	if w := call("PATCH", path, "new", ""); w.Code != 403 {
		t.Fatalf("unsigned chunk: %d %s", w.Code, w.Body)
	}
	if w := call("PATCH", path, "new", sign("upload_chunk", session.ID, "other", policy(`["create","update"]`))); w.Code != 403 {
		t.Fatalf("other actor: %d %s", w.Code, w.Body)
	}
	if w := call("PATCH", path, "new", sign("upload_chunk", session.ID, "actor", policy(`["create","update"]`))); w.Code != 200 {
		t.Fatalf("chunk: %d %s", w.Code, w.Body)
	}
	if w := call("POST", path+"/complete", "{}", sign("upload_complete", session.ID, "actor", policy(`["create"]`))); w.Code != 403 {
		t.Fatalf("revoked update: %d %s", w.Code, w.Body)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "file.txt")); string(data) != "original" {
		t.Fatalf("destination changed after denial: %q", data)
	}
	if w := call("POST", path+"/complete", "{}", sign("upload_complete", session.ID, "actor", policy(`["create","update"]`))); w.Code != 201 {
		t.Fatalf("complete: %d %s", w.Code, w.Body)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "file.txt")); string(data) != "new" {
		t.Fatalf("destination not published: %q", data)
	}
	credential = "credential"
	hidden := json.RawMessage(`{"version":1,"rules":[{"policy_id":"allow","path":"nodes/node/files/mounts/m/**","capabilities":["create","update"]},{"policy_id":"deny","path":"nodes/node/files/mounts/m/**","capabilities":["deny","read"],"file_types":{"extensions":["txt"]}}]}`)
	if w := call("POST", base, body, sign("upload_create", signedauth.UploadAdmissionBodyID([]byte(body)), "actor", hidden)); w.Code != 404 {
		t.Fatalf("hidden destination overwrite: %d %s", w.Code, w.Body)
	}
	w = call("POST", base, body, admission)
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &session) != nil {
		t.Fatalf("second admission: %d %s", w.Code, w.Body)
	}
	path = base + "/" + session.ID
	if w := call("DELETE", path, "", ""); w.Code != 403 {
		t.Fatalf("unsigned abort: %d %s", w.Code, w.Body)
	}
	if w := call("DELETE", path, "", sign("upload_abort", session.ID, "actor", policy(`["read"]`))); w.Code != 403 {
		t.Fatalf("revoked abort: %d %s", w.Code, w.Body)
	}
	if w := call("DELETE", path, "", sign("upload_abort", session.ID, "actor", policy(`["create"]`))); w.Code != 204 {
		t.Fatalf("signed abort: %d %s", w.Code, w.Body)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "file.txt")); string(data) != "new" {
		t.Fatalf("abort changed destination: %q", data)
	}
	w = call("POST", base, body, admission)
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &session) != nil {
		t.Fatalf("slow admission: %d %s", w.Code, w.Body)
	}
	now := time.Now().Unix()
	short, err := signedauth.Sign(signedauth.Claims{Version: 1, KeyID: "key", IssuedAt: now, ExpiresAt: now + 2,
		Context: policy(`["create","update"]`), Binding: signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: "upload_chunk", RequestID: "request", DestinationNodeID: "node", DestinationMountID: "m", DestinationRoot: "file.txt", PlanID: session.ID}}, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "PATCH %s/%s HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer secret\r\nX-Jolt-Access-Authorization: %s\r\nContent-Range: bytes 0-2/3\r\nContent-Length: 3\r\n\r\nn", base, session.ID, short); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var response [256]byte
	n, err := conn.Read(response[:])
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("slow upload exceeded its authorization deadline")
	}
	if n > 0 && strings.Contains(string(response[:n]), " 200 ") {
		t.Fatalf("slow upload reported success: %s", response[:n])
	}
	if data, _ := os.ReadFile(filepath.Join(root, "file.txt")); string(data) != "new" {
		t.Fatalf("expired chunk changed destination: %q", data)
	}
	query := "path=simple.txt&overwrite=false"
	simpleToken := func(actor, query, idempotency string, context json.RawMessage) string {
		now := time.Now().Unix()
		claims := signedauth.Claims{Version: 1, KeyID: "key", IssuedAt: now, ExpiresAt: now + 20, Context: context,
			Binding: signedauth.Binding{ActorID: actor, CredentialID: "credential", Operation: "upload_simple", RequestID: "request", DestinationNodeID: "node", DestinationMountID: "m", DestinationRoot: "simple.txt", PlanID: signedauth.SimpleUploadPlanID(query, idempotency)}}
		token, err := signedauth.Sign(claims, key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	simpleCall := func(query, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/v1/mounts/m/files/content?"+query, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set(signedAuthorizationHeader, token)
		r.Header.Set("Idempotency-Key", "same-key")
		w := &signedUploadRecorder{httptest.NewRecorder()}
		h.ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	simple := simpleToken("actor", query, "same-key", policy(`["create","update"]`))
	if w := simpleCall("path=simple.txt&overwrite=true", simple, "bad"); w.Code != 403 {
		t.Fatalf("changed simple upload options: %d %s", w.Code, w.Body)
	}
	if w := simpleCall(query, simpleToken("actor", query, "same-key", denied), "bad"); w.Code != 403 {
		t.Fatalf("typed simple upload denial: %d %s", w.Code, w.Body)
	}
	if w := simpleCall(query, simple, "ok"); w.Code != 201 {
		t.Fatalf("simple upload: %d %s", w.Code, w.Body)
	}
	if w := simpleCall(query, simple, "different"); w.Code != 200 {
		t.Fatalf("simple upload retry: %d %s", w.Code, w.Body)
	}
	if w := simpleCall(query, simpleToken("other", query, "same-key", policy(`["create","update"]`)), "different"); w.Code != 409 {
		t.Fatalf("cross-actor idempotency: %d %s", w.Code, w.Body)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "simple.txt")); string(data) != "ok" {
		t.Fatalf("simple destination changed: %q", data)
	}
	slowQuery := "path=slow.txt&overwrite=false"
	now = time.Now().Unix()
	slowToken, err := signedauth.Sign(signedauth.Claims{Version: 1, KeyID: "key", IssuedAt: now, ExpiresAt: now + 2, Context: policy(`["create","update"]`),
		Binding: signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: "upload_simple", RequestID: "request", DestinationNodeID: "node", DestinationMountID: "m", DestinationRoot: "slow.txt", PlanID: signedauth.SimpleUploadPlanID(slowQuery, "")}}, key)
	if err != nil {
		t.Fatal(err)
	}
	slowConn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slowConn.Close()
	if _, err := fmt.Fprintf(slowConn, "PUT /api/v1/mounts/m/files/content?%s HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer secret\r\nX-Jolt-Access-Authorization: %s\r\nContent-Length: 3\r\n\r\nn", slowQuery, slowToken); err != nil {
		t.Fatal(err)
	}
	if err := slowConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = slowConn.Read(response[:])
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("slow simple upload exceeded its authorization deadline")
	}
	if n > 0 && (strings.Contains(string(response[:n]), " 200 ") || strings.Contains(string(response[:n]), " 201 ")) {
		t.Fatalf("slow simple upload reported success: %s", response[:n])
	}
	if _, err := os.Stat(filepath.Join(root, "slow.txt")); !os.IsNotExist(err) {
		t.Fatalf("expired simple upload was published: %v", err)
	}
}
