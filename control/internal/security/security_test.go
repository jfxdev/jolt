package security

import "testing"

func TestArgon2PasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("a-very-long-password")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "a-very-long-password") {
		t.Fatal("valid password was rejected")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("invalid password was accepted")
	}
}

func TestEncryptionRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	encrypted, err := Encrypt(key, "node-secret")
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == "node-secret" {
		t.Fatal("plaintext was not encrypted")
	}
	plain, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "node-secret" {
		t.Fatalf("decrypted value = %q", plain)
	}
}
