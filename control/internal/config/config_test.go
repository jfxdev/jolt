package config

import "testing"

func TestValidateNodeEndpoint(t *testing.T) {
	got, err := ValidateNodeEndpoint("https://node.example.test:8443/api?ignored=true")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://node.example.test:8443" {
		t.Fatalf("endpoint = %q", got)
	}
}

func TestValidateNodeEndpointRejectsUnsupportedScheme(t *testing.T) {
	if _, err := ValidateNodeEndpoint("file:///etc/passwd"); err == nil {
		t.Fatal("expected validation error")
	}
}
