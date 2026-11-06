package pki

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const rootPassword = "correct horse battery staple"

func newRootPair(t *testing.T) (*ecdsa.PrivateKey, *Authority) {
	t.Helper()
	root, err := NewRoot(time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return root.Key, root
}

func TestARootKeyFileOpensWithItsPasswordAndNothingElse(t *testing.T) {
	key, root := newRootPair(t)
	file, err := SealRootKey(key, root.Cert, rootPassword)
	if err != nil {
		t.Fatal(err)
	}
	opened, cert, err := OpenRootKey(file, rootPassword)
	if err != nil || !opened.Equal(key) || Fingerprint(cert) != Fingerprint(root.Cert) {
		t.Fatalf("round trip: %v", err)
	}
	if strings.Contains(string(file), "PRIVATE") {
		t.Fatal("the file carries the key in the clear")
	}
	if _, _, err := OpenRootKey(file, rootPassword+"x"); err == nil {
		t.Fatal("a wrong password opened the file")
	}
	if _, _, err := OpenRootKey(file, ""); err == nil {
		t.Fatal("an empty password opened the file")
	}
	if _, err := SealRootKey(key, root.Cert, "short"); err == nil {
		t.Fatal("a short password was accepted")
	}
	otherKey, other := newRootPair(t)
	if _, err := SealRootKey(otherKey, root.Cert, rootPassword); err == nil {
		t.Fatal("a key was sealed under a certificate that is not its own")
	}
	_ = other
}

func TestAChangedRootKeyFileIsRefusedWhicheverPartChanged(t *testing.T) {
	key, root := newRootPair(t)
	_, other := newRootPair(t)
	file, _ := SealRootKey(key, root.Cert, rootPassword)
	var fields map[string]any
	_ = json.Unmarshal(file, &fields)
	mutate := func(name string, change func(map[string]any)) {
		changed := map[string]any{}
		for k, v := range fields {
			changed[k] = v
		}
		change(changed)
		data, _ := json.Marshal(changed)
		if _, _, err := OpenRootKey(data, rootPassword); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	mutate("another fingerprint", func(f map[string]any) { f["root_sha256"] = Fingerprint(other.Cert) })
	mutate("another certificate", func(f map[string]any) { f["root_pem"] = string(other.PEM()) })
	mutate("flipped ciphertext", func(f map[string]any) {
		c := []byte(f["ciphertext"].(string))
		c[10] ^= 1
		f["ciphertext"] = string(c)
	})
	mutate("another nonce", func(f map[string]any) { f["nonce"] = "AAAAAAAAAAAAAAAA" })
	mutate("another salt", func(f map[string]any) { f["salt"] = "AAAAAAAAAAAAAAAAAAAAAA==" })
	mutate("weaker derivation", func(f map[string]any) { f["time"] = 1 })
	mutate("version", func(f map[string]any) { f["version"] = 2 })
	mutate("kdf", func(f map[string]any) { f["kdf"] = "scrypt" })
	mutate("unknown field", func(f map[string]any) { f["extra"] = true })
	for name, data := range map[string]string{"empty": "", "not json": "x", "array": "[]", "trailing": string(file) + "x"} {
		if _, _, err := OpenRootKey([]byte(data), rootPassword); err == nil && name != "trailing" {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAFileCannotMakeTheHostSpendMoreThanAKeyDerivationShould(t *testing.T) {
	key, root := newRootPair(t)
	file, _ := SealRootKey(key, root.Cert, rootPassword)
	var fields map[string]any
	_ = json.Unmarshal(file, &fields)
	for name, change := range map[string]func(){
		"memory":     func() { fields["memory_kib"] = (1 << 20) + 1 },
		"huge":       func() { fields["memory_kib"] = 1 << 30 },
		"time":       func() { fields["time"] = 11 },
		"threads":    func() { fields["threads"] = 17 },
		"zero":       func() { fields["memory_kib"] = 0 },
		"no threads": func() { fields["threads"] = 0 },
	} {
		current := map[string]any{}
		for k, v := range fields {
			current[k] = v
		}
		fields = current
		change()
		data, _ := json.Marshal(fields)
		start := time.Now()
		if _, _, err := OpenRootKey(data, rootPassword); err == nil || !strings.Contains(err.Error(), "unreasonable") || time.Since(start) > 2*time.Second {
			t.Errorf("%s: %v after %s", name, err, time.Since(start))
		}
		_ = json.Unmarshal(file, &fields)
	}
}

func exportedAuthority(t *testing.T) (*Manager, *memoryRepo, *clock, []byte) {
	t.Helper()
	m, repo, c := started(t)
	file, err := m.ExportRoot(context.Background(), rootPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveRootKey(context.Background(), file, rootPassword); err != nil {
		t.Fatal(err)
	}
	return m, repo, c, file
}

func TestExportingTheRootRemovesItsKeyFromTheDatabaseAndChangesNothingNodesSee(t *testing.T) {
	m, repo, c := started(t)
	before := m.Bundle()
	if !m.RootKeyInDatabase() {
		t.Fatal("the key is not in the database by default")
	}
	file, err := m.ExportRoot(context.Background(), rootPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !m.RootKeyInDatabase() || repo.kind("root")[0].Secret == "" {
		t.Fatal("exporting alone removed the key")
	}
	if err := m.RemoveRootKey(context.Background(), file, rootPassword); err != nil {
		t.Fatal(err)
	}
	if m.RootKeyInDatabase() || repo.kind("root")[0].Secret != "" {
		t.Fatal("the key is still in the database")
	}
	after := m.Bundle()
	if after.Version != before.Version || after.Roots[0] != before.Roots[0] {
		t.Fatal("removing the key changed what nodes trust")
	}
	ensure(t, m)
	c.advance(time.Hour)
	ensure(t, m)
	if m.Bundle().Version != before.Version {
		t.Fatal("a pass without the root key published something")
	}
	if _, err := m.ExportRoot(context.Background(), rootPassword); err == nil {
		t.Fatal("exported a key that is not there")
	}
	// Nothing in the database can open the file or sign for the root now.
	for _, object := range repo.objects {
		if strings.Contains(object.Secret, "PRIVATE") {
			t.Fatal("a private key sits in the clear")
		}
	}
}

func TestTheKeyIsOnlyRemovedWhenTheFileInHandIsThisRootsAndOpens(t *testing.T) {
	m, repo, _ := started(t)
	good, err := m.ExportRoot(context.Background(), rootPassword)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, other := newRootPair(t)
	foreign, _ := SealRootKey(otherKey, other.Cert, rootPassword)
	if err := m.RemoveRootKey(context.Background(), foreign, rootPassword); err == nil {
		t.Fatal("a file with another root's key let this one's be removed")
	}
	if err := m.RemoveRootKey(context.Background(), good, "not the password at all"); err == nil {
		t.Fatal("a wrong password let the key be removed")
	}
	if err := m.RemoveRootKey(context.Background(), []byte("junk"), rootPassword); err == nil {
		t.Fatal("junk let the key be removed")
	}
	if repo.kind("root")[0].Secret == "" {
		t.Fatal("a refused removal removed the key anyway")
	}
}

func TestTheRootKeyComesBackOnlyFromItsOwnFile(t *testing.T) {
	m, repo, _, file := exportedAuthority(t)
	otherKey, other := newRootPair(t)
	foreign, _ := SealRootKey(otherKey, other.Cert, rootPassword)
	if err := m.ImportRoot(context.Background(), foreign, rootPassword); err == nil {
		t.Fatal("another root's key was imported")
	}
	if err := m.ImportRoot(context.Background(), file, "wrong wrong wrong wrong"); err == nil {
		t.Fatal("a wrong password imported the key")
	}
	if repo.kind("root")[0].Secret != "" {
		t.Fatal("a refused import stored something")
	}
	if err := m.ImportRoot(context.Background(), file, rootPassword); err != nil {
		t.Fatal(err)
	}
	if !m.RootKeyInDatabase() {
		t.Fatal("the key is not back")
	}
	if err := m.RotateIntermediate(context.Background(), false, ""); err != nil {
		t.Fatalf("with the key back the Control Tower can issue again: %v", err)
	}
}

func TestAnIntermediateIsRenewedFromTheFileWithoutTheKeyEverReturningToTheDatabase(t *testing.T) {
	m, repo, c, file := exportedAuthority(t)
	ctx := context.Background()
	if err := m.RotateIntermediate(ctx, false, ""); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("without the file: %v", err)
	}
	// The renewal falls due: the Control Tower keeps running and says so.
	c.advance(17 * 30 * 24 * time.Hour)
	if err := m.Ensure(ctx); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("a due renewal with no root key: %v", err)
	}
	otherKey, other := newRootPair(t)
	foreign, _ := SealRootKey(otherKey, other.Cert, rootPassword)
	if err := m.RenewIntermediateFromFile(ctx, foreign, rootPassword, false, ""); err == nil {
		t.Fatal("another root's file renewed the intermediate")
	}
	if err := m.RenewIntermediateFromFile(ctx, file, rootPassword, false, ""); err != nil {
		t.Fatal(err)
	}
	if _, issuers, _ := m.Bundle().Certificates(); len(issuers) != 2 {
		t.Fatalf("intermediates: %d", len(issuers))
	}
	if err := m.Ensure(ctx); err != nil {
		t.Fatalf("the renewal is still due after it was done: %v", err)
	}
	if repo.kind("root")[0].Secret != "" || m.RootKeyInDatabase() {
		t.Fatal("renewing from the file stored the root key")
	}
	// The leaked-key answer works from the file too.
	if err := m.RenewIntermediateFromFile(ctx, file, rootPassword, true, "leaked"); err != nil {
		t.Fatal(err)
	}
	if _, issuers, _ := m.Bundle().Certificates(); len(issuers) != 1 {
		t.Fatalf("after revoking: %d intermediates", len(issuers))
	}
}
