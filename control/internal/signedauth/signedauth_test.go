package signedauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture() (Claims, ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	binding := Binding{ActorID: "user-1", CredentialID: "credential-1", Operation: "copy", RequestID: "job-1", SourceNodeID: "source", SourceGrantID: "grant-1", SourceMountID: "m1", SourceRoot: "private/docs", DestinationNodeID: "destination", DestinationGrantID: "grant-2", DestinationMountID: "m2", DestinationRoot: ".", PlanID: "plan-1"}
	claims := Claims{Version: Version, KeyID: "key-1", Binding: binding, IssuedAt: 1700000000, ExpiresAt: 1700000030, Context: json.RawMessage(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/source/files/mounts/m1/**","capabilities":["read"]}]}`)}
	return claims, key, map[string]ed25519.PublicKey{"key-1": key.Public().(ed25519.PublicKey)}
}

func TestVerifyBindingExpiryAndKeyRotation(t *testing.T) {
	claims, key, keys := fixture()
	token, err := Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var golden []byte
	for {
		golden, err = os.ReadFile(filepath.Join(dir, "testdata", "signed-authorization-sha256.txt"))
		if err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("shared signed authorization fixture not found")
		}
		dir = parent
	}
	if got := fmt.Sprintf("%x", sum); got != strings.TrimSpace(string(golden)) {
		t.Fatalf("signed authorization differs from shared fixture: %s", got)
	}
	now := time.Unix(claims.IssuedAt, 0)
	for _, node := range []string{"source", "destination"} {
		got, filter, err := Verify(token, keys, claims.Binding, node, now)
		if err != nil || filter == nil || got.Binding != claims.Binding {
			t.Fatalf("verify %s: %+v %v", node, got, err)
		}
		decision := filter.Evaluate("nodes/source/files/mounts/m1/private/docs/file.txt", "read", "file")
		if !decision.Allowed {
			t.Fatalf("filter lost policy: %+v", decision)
		}
	}
	checks := []struct {
		name    string
		binding Binding
		node    string
		now     time.Time
		keys    map[string]ed25519.PublicKey
	}{
		{"expired", claims.Binding, "source", time.Unix(claims.ExpiresAt, 0), keys},
		{"before issued", claims.Binding, "source", now.Add(-time.Second), keys},
		{"wrong node", claims.Binding, "other", now, keys},
		{"unknown key", claims.Binding, "source", now, map[string]ed25519.PublicKey{}},
	}
	mismatched := []func(*Binding){
		func(b *Binding) { b.ActorID = "other" }, func(b *Binding) { b.CredentialID = "other" }, func(b *Binding) { b.Operation = "move" }, func(b *Binding) { b.RequestID = "other" },
		func(b *Binding) { b.SourceNodeID = "other" }, func(b *Binding) { b.SourceGrantID = "other" }, func(b *Binding) { b.SourceMountID = "other" }, func(b *Binding) { b.SourceRoot = "private" },
		func(b *Binding) { b.DestinationNodeID = "other" }, func(b *Binding) { b.DestinationGrantID = "other" }, func(b *Binding) { b.DestinationMountID = "other" }, func(b *Binding) { b.DestinationRoot = "other" }, func(b *Binding) { b.PlanID = "other" },
	}
	for i, change := range mismatched {
		binding := claims.Binding
		change(&binding)
		checks = append(checks, struct {
			name    string
			binding Binding
			node    string
			now     time.Time
			keys    map[string]ed25519.PublicKey
		}{fmt.Sprint("binding ", i), binding, "source", now, keys})
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Verify(token, tc.keys, tc.binding, tc.node, tc.now); err == nil {
				t.Fatal("invalid authorization accepted")
			}
		})
	}
	// During rotation either configured key verifies; removing the old key
	// immediately prevents any new use of its signed contexts.
	newSeed := make([]byte, ed25519.SeedSize)
	for i := range newSeed {
		newSeed[i] = byte(i + 1)
	}
	newKey := ed25519.NewKeyFromSeed(newSeed)
	rotated := claims
	rotated.KeyID = "key-2"
	newToken, err := Sign(rotated, newKey)
	if err != nil {
		t.Fatal(err)
	}
	keys["key-2"] = newKey.Public().(ed25519.PublicKey)
	if _, _, err := Verify(newToken, keys, claims.Binding, "source", now); err != nil {
		t.Fatalf("new key rejected: %v", err)
	}
	delete(keys, "key-1")
	if _, _, err := Verify(token, keys, claims.Binding, "source", now); err == nil {
		t.Fatal("retired key accepted")
	}
	keys["key-1"] = key.Public().(ed25519.PublicKey)
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig[0] ^= 1
	if _, _, err := Verify(parts[0]+"."+base64.RawURLEncoding.EncodeToString(sig), keys, claims.Binding, "source", now); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestRejectInvalidClaimsAndAmbiguousJSON(t *testing.T) {
	claims, key, keys := fixture()
	tests := []struct {
		name   string
		mutate func(*Claims)
	}{
		{"version", func(c *Claims) { c.Version = 2 }}, {"duration", func(c *Claims) { c.ExpiresAt++ }},
		{"missing actor", func(c *Claims) { c.Binding.ActorID = "" }}, {"missing credential", func(c *Claims) { c.Binding.CredentialID = "" }},
		{"traversal", func(c *Claims) { c.Binding.SourceRoot = "../secret" }}, {"absolute", func(c *Claims) { c.Binding.DestinationRoot = "/etc" }},
		{"ambiguous whitespace", func(c *Claims) { c.Binding.SourceRoot = " secret" }},
		{"no node", func(c *Claims) { c.Binding.SourceNodeID = ""; c.Binding.DestinationNodeID = "" }},
		{"bad filter", func(c *Claims) { c.Context = json.RawMessage(`{"version":1,"rules":[],"bad":1}`) }},
		{"oversize filter", func(c *Claims) { c.Context = json.RawMessage(`{"version":1,"rules":[]}` + strings.Repeat(" ", 33000)) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := claims
			tc.mutate(&c)
			if _, err := Sign(c, key); err == nil {
				t.Fatal("invalid claims signed")
			}
		})
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), `"version":1`, `"version":1,"Version":1`, 1))
	sig := ed25519.Sign(key, append([]byte(domain), payload...))
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, _, err := Verify(token, keys, claims.Binding, "source", time.Unix(claims.IssuedAt, 0)); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestVerifyLocalReadUsesExactRouteAndRejectsTransferTokens(t *testing.T) {
	claims, key, keys := fixture()
	claims.Binding.Operation = "content"
	claims.Binding.SourceGrantID = ""
	claims.Binding.DestinationNodeID, claims.Binding.DestinationGrantID, claims.Binding.DestinationMountID, claims.Binding.DestinationRoot, claims.Binding.PlanID = "", "", "", "", ""
	token, err := Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(claims.IssuedAt, 0)
	if _, _, err := VerifyLocalRead(token, keys, "source", "content", "m1", "private/docs", now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ node, operation, mount, root string }{
		{"other", "content", "m1", "private/docs"},
		{"source", "metadata", "m1", "private/docs"},
		{"source", "content", "other", "private/docs"},
		{"source", "content", "m1", "private"},
		{"source", "delete", "m1", "private/docs"},
	} {
		if _, _, err := VerifyLocalRead(token, keys, tc.node, tc.operation, tc.mount, tc.root, now); err == nil {
			t.Fatalf("accepted different route: %+v", tc)
		}
	}
	claims.Binding.SourceGrantID = "grant"
	token, err = Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyLocalRead(token, keys, "source", "content", "m1", "private/docs", now); err == nil {
		t.Fatal("transfer token accepted for local read")
	}
}
