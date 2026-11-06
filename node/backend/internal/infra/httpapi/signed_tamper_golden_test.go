package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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

const tamperDomain = "jolt-signed-authorization-v1\x00"

// TestSignedReadRefusesEveryTamperedEnvelope sends a signed read that the node
// would answer (404 for a hidden key) after changing one thing at a time. Each
// variant must be refused outright: never served, and never answered as if the
// policy had been verified, since a verified answer means the forged context
// was accepted.
func TestSignedReadRefusesEveryTamperedEnvelope(t *testing.T) {
	roots := map[string]string{"editor": t.TempDir(), "other": t.TempDir()}
	for _, root := range roots {
		for name, body := range map[string]string{"good.txt": "hello", "secret.pem": "TOPSECRET"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	files := filesystem.New(store)
	for id, root := range roots {
		if _, err := files.SaveMount(context.Background(), entities.Mount{ID: id, Name: id, LocalPath: root, Mode: "read_write", Enabled: true, Published: true}); err != nil {
			t.Fatal(err)
		}
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	stranger := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	cfg := config.Config{ControlTowerToken: "secret", AuthorizationKeys: map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, SearchMaxResults: 200, SearchMaxEntries: 10000, SearchTimeout: time.Second, DiskUsageMaxEntries: 10000, DiskUsageTimeout: time.Second, ArchiveMaxEntries: 1000, ArchiveMaxBytes: 1 << 20}
	identity := entities.Identity{NodeID: "node"}
	handler := New(cfg, identity, files, jobs.New(store, files), pairing.New(store, identity), grants.New(store, files), slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.NewRegistry())

	const mountPath = "nodes/node/files/mounts/editor/**"
	denyContext := `{"version":1,"rules":[{"policy_id":"allow","path":"` + mountPath + `","capabilities":["list","read"]},{"policy_id":"no-keys","path":"` + mountPath + `","capabilities":["deny","read"],"file_types":{"extensions":["pem"]}}]}`
	allowAll := `{"version":1,"rules":[{"policy_id":"allow","path":"` + mountPath + `","capabilities":["list","read"]}]}`
	now := time.Now().Unix()
	claims := func(change func(*signedauth.Claims)) signedauth.Claims {
		c := signedauth.Claims{Version: 1, KeyID: "key", IssuedAt: now, ExpiresAt: now + 20, Context: json.RawMessage(denyContext),
			Binding: signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: "content", RequestID: "request", SourceNodeID: "node", SourceMountID: "editor", SourceRoot: "secret.pem"}}
		if change != nil {
			change(&c)
		}
		return c
	}
	sign := func(c signedauth.Claims) string {
		token, err := signedauth.Sign(c, key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	signRaw := func(payload []byte, with ed25519.PrivateKey) string {
		signature := ed25519.Sign(with, append([]byte(tamperDomain), payload...))
		return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	// editPayload changes the signed JSON and keeps the original signature.
	editPayload := func(token string, edit func(map[string]any)) string {
		parts := strings.SplitN(token, ".", 2)
		raw, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		edit(payload)
		changed, _ := json.Marshal(payload)
		return base64.RawURLEncoding.EncodeToString(changed) + "." + parts[1]
	}
	call := func(target string, headers ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("Authorization", "Bearer secret")
		for _, value := range headers {
			r.Header.Add(signedAuthorizationHeader, value)
		}
		w := &signedResponseRecorder{httptest.NewRecorder()}
		handler.ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	const content = "/api/v1/mounts/editor/files/content?path=secret.pem"

	valid := sign(claims(nil))
	// The untouched envelope is what the variants are measured against: verified
	// and answered as a hidden file.
	if w := call(content, valid); w.Code != 404 || w.Header().Get("X-Jolt-Access-Applied") != "v1" {
		t.Fatalf("baseline: %d %s", w.Code, w.Body)
	}
	good := sign(claims(func(c *signedauth.Claims) { c.Binding.SourceRoot = "good.txt" }))
	if w := call("/api/v1/mounts/editor/files/content?path=good.txt", good); w.Code != 200 || w.Body.String() != "hello" {
		t.Fatalf("baseline for an allowed file: %d %s", w.Code, w.Body)
	}

	payload, _ := json.Marshal(claims(nil))
	var tamperedPayload map[string]any
	_ = json.Unmarshal(payload, &tamperedPayload)
	longLived := claims(func(c *signedauth.Claims) { c.ExpiresAt = c.IssuedAt + 20 })
	longLivedPayload, _ := json.Marshal(longLived)
	longLivedPayload = []byte(strings.Replace(string(longLivedPayload), `"expires_at":`+itoa(now+20), `"expires_at":`+itoa(now+3600), 1))
	duplicateKey := strings.Replace(string(payload), `"version":1`, `"version":1,"version":1`, 1)
	unknownField := strings.Replace(string(payload), `"version":1`, `"version":1,"admin":true`, 1)
	otherSignature := strings.SplitN(sign(claims(func(c *signedauth.Claims) { c.Binding.RequestID = "another" })), ".", 2)[1]
	parts := strings.SplitN(valid, ".", 2)
	flip := func(s string) string {
		b := []byte(s)
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		return string(b)
	}

	type variant struct {
		name    string
		target  string
		headers []string
	}
	cases := []variant{
		{"deny rule removed, signature kept", content, []string{editPayload(valid, func(p map[string]any) { p["context"] = json.RawMessage(allowAll) })}},
		{"context swapped for an allow-all one", content, []string{editPayload(valid, func(p map[string]any) {
			var c map[string]any
			_ = json.Unmarshal([]byte(allowAll), &c)
			p["context"] = c
		})}},
		{"expiry pushed out, signature kept", content, []string{editPayload(valid, func(p map[string]any) { p["expires_at"] = now + 3600 })}},
		{"actor changed, signature kept", content, []string{editPayload(valid, func(p map[string]any) { p["binding"].(map[string]any)["actor_id"] = "admin" })}},
		{"signature of another envelope", content, []string{parts[0] + "." + otherSignature}},
		{"signature bit flipped", content, []string{parts[0] + "." + flip(parts[1])}},
		{"payload bit flipped", content, []string{flip(parts[0]) + "." + parts[1]}},
		{"signature truncated", content, []string{parts[0] + "." + parts[1][:len(parts[1])-4]}},
		{"signature missing", content, []string{parts[0] + "."}},
		{"payload missing", content, []string{"." + parts[1]}},
		{"no separator", content, []string{parts[0] + parts[1]}},
		{"extra segment", content, []string{valid + ".AAAA"}},
		{"padded base64", content, []string{parts[0] + "=." + parts[1]}},
		{"surrounding spaces", content, []string{" " + valid + " "}},
		{"empty header", content, []string{""}},
		{"signed by a key the node does not trust", content, []string{signRaw(payload, stranger)}},
		{"unknown key id", content, []string{editPayload(valid, func(p map[string]any) { p["key_id"] = "rotated-away" })}},
		{"version 2", content, []string{signRaw([]byte(strings.Replace(string(payload), `"version":1`, `"version":2`, 1)), key)}},
		{"expired a minute ago", content, []string{sign(claims(func(c *signedauth.Claims) { c.IssuedAt, c.ExpiresAt = now-90, now-60 }))}},
		{"issued in the future", content, []string{sign(claims(func(c *signedauth.Claims) { c.IssuedAt, c.ExpiresAt = now+600, now+620 }))}},
		{"validly signed but longer than 30 seconds", content, []string{signRaw(longLivedPayload, key)}},
		{"validly signed with a duplicate JSON key", content, []string{signRaw([]byte(duplicateKey), key)}},
		{"validly signed with an unknown field", content, []string{signRaw([]byte(unknownField), key)}},
		{"two headers, the valid one first", content, []string{valid, valid}},
		{"two headers, a forged one second", content, []string{valid, editPayload(valid, func(p map[string]any) { p["expires_at"] = now + 3600 })}},
		{"replayed for another file", "/api/v1/mounts/editor/files/content?path=good.txt", []string{valid}},
		{"replayed for another operation", "/api/v1/mounts/editor/files/metadata?path=secret.pem", []string{valid}},
		{"replayed for another mount", "/api/v1/mounts/other/files/content?path=secret.pem", []string{valid}},
		{"replayed for a listing", "/api/v1/mounts/editor/files", []string{valid}},
		{"replayed on a mutation", "/api/v1/mounts/editor/files?path=secret.pem", []string{valid}},
		{"another node as the source", content, []string{sign(claims(func(c *signedauth.Claims) { c.Binding.SourceNodeID = "elsewhere" }))}},
		{"another mount in the binding", content, []string{sign(claims(func(c *signedauth.Claims) { c.Binding.SourceMountID = "other" }))}},
		{"another root in the binding", content, []string{sign(claims(func(c *signedauth.Claims) { c.Binding.SourceRoot = "good.txt" }))}},
		{"a job operation for a read", content, []string{sign(claims(func(c *signedauth.Claims) { c.Binding.Operation = "copy_local" }))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := call(tc.target, tc.headers...)
			if w.Code < 400 || w.Code == http.StatusNotFound {
				t.Fatalf("status %d, a verified answer or success: %s", w.Code, w.Body)
			}
			if strings.Contains(w.Body.String(), "TOPSECRET") || strings.Contains(w.Body.String(), "hello") {
				t.Fatalf("file content served: %s", w.Body)
			}
			if w.Header().Get("X-Jolt-Access-Applied") != "" {
				t.Fatal("answered as if a policy context had been applied")
			}
		})
	}
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }
