package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/jfxdev/jolt/control/internal/config"
)

type rotatingSource struct {
	mu   sync.Mutex
	id   string
	keys map[string]ed25519.PrivateKey
}

func newRotatingSource() *rotatingSource {
	return &rotatingSource{keys: map[string]ed25519.PrivateKey{}}
}

func (r *rotatingSource) rotate(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	r.keys[id], r.id = key, id
}

func (r *rotatingSource) Current() (string, ed25519.PrivateKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.id, r.keys[r.id]
}

func (r *rotatingSource) Public() map[string]ed25519.PublicKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]ed25519.PublicKey{}
	for id, key := range r.keys {
		out[id] = key.Public().(ed25519.PublicKey)
	}
	return out
}

func TestTheSigningKeyComesFromTheSourceWhenThereIsOne(t *testing.T) {
	source := newRotatingSource()
	source.rotate("first")
	s := &Server{config: config.Config{SigningSource: source, AuthorizationSigningKeyID: "ignored"}}
	id, key := s.signing()
	if id != "first" || len(key) != ed25519.PrivateKeySize || s.signingKeyID() != "first" {
		t.Fatalf("source not used: %q", id)
	}
	source.rotate("second")
	if id, _ := s.signing(); id != "second" {
		t.Fatalf("a rotation was not seen: %q", id)
	}
	keys := s.verificationKeys()
	if len(keys) != 2 || keys["first"] == nil || keys["second"] == nil {
		t.Fatalf("verification keys: %v", keys)
	}
}

func TestAFixedKeyStillWorksAndAnAbsentKeyVerifiesNothing(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{config: config.Config{AuthorizationSigningKeyID: "fixed", AuthorizationSigningKey: private}}
	if id, key := s.signing(); id != "fixed" || !key.Equal(private) {
		t.Fatal("fixed key")
	}
	if keys := s.verificationKeys(); len(keys) != 1 || !keys["fixed"].Equal(private.Public()) {
		t.Fatalf("verification keys: %v", keys)
	}
	none := &Server{}
	if len(none.signingKey()) != 0 || len(none.verificationKeys()) != 0 {
		t.Fatal("an absent key produced material")
	}
}
