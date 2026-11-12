package tfprovider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/rbac"
)

func TestClientManagesPolicies(t *testing.T) {
	controlURL, _ := newControl(t)
	client, err := NewClient(controlURL, testToken, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	input := PolicyInput{Name: "media-read", Description: "media", Rules: []rbac.Rule{{Path: "nodes/n1/files/mounts/media/**", Capabilities: []string{"read", "list"}}}}
	created, err := client.CreatePolicy(ctx, input)
	if err != nil || created.ID == "" || created.Name != "media-read" {
		t.Fatalf("create: %+v %v", created, err)
	}
	if got, err := client.GetPolicy(ctx, created.ID); err != nil || got.Name != "media-read" || len(got.Rules) != 1 {
		t.Fatalf("get: %+v %v", got, err)
	}
	// The search matches substrings; only the exact name is taken.
	if _, err := client.CreatePolicy(ctx, PolicyInput{Name: "media-read-extra", Rules: input.Rules}); err != nil {
		t.Fatal(err)
	}
	if got, err := client.FindPolicyByName(ctx, "media-read"); err != nil || got.ID != created.ID {
		t.Fatalf("find: %+v %v", got, err)
	}
	if _, err := client.FindPolicyByName(ctx, "media"); !isStatus(err, http.StatusNotFound) {
		t.Fatalf("partial name found a policy: %v", err)
	}
	input.Description = "media, changed"
	if updated, err := client.UpdatePolicy(ctx, created.ID, input); err != nil || updated.Description != "media, changed" {
		t.Fatalf("update: %+v %v", updated, err)
	}
	if err := client.DeletePolicy(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetPolicy(ctx, created.ID); !isStatus(err, http.StatusNotFound) {
		t.Fatalf("deleted policy still read: %v", err)
	}
}

func TestClientKeepsTheRefusal(t *testing.T) {
	controlURL, _ := newControl(t)
	client, err := NewClient(controlURL, testToken, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreatePolicy(context.Background(), PolicyInput{Name: "terraform", Rules: []rbac.Rule{{Path: "nodes/n1", Capabilities: []string{"read"}}}})
	var failure *APIError
	if !errors.As(err, &failure) || failure.Status != http.StatusConflict || failure.Code != "policy_conflict" || !strings.HasPrefix(failure.CorrelationID, "tf_") {
		t.Fatalf("refusal: %#v", err)
	}

	stranger, err := NewClient(controlURL, "not-a-token", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.GetPolicy(context.Background(), "terraform"); !isStatus(err, http.StatusUnauthorized) {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestNewClientRefusesUnsafeURLs(t *testing.T) {
	for _, raw := range []string{
		"http://jolt.example.com",
		"https://user:pass@jolt.example.com",
		"https://jolt.example.com/api",
		"https://jolt.example.com?x=1",
		"jolt.example.com",
	} {
		if _, err := NewClient(raw, testToken, ""); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{"https://jolt.example.com", "https://jolt.example.com/", "http://127.0.0.1:8080", "http://localhost:8080"} {
		if _, err := NewClient(raw, testToken, ""); err != nil {
			t.Errorf("refused %s: %v", raw, err)
		}
	}
	if _, err := NewClient("https://jolt.example.com", " ", ""); err == nil {
		t.Error("accepted an empty token")
	}
}

func TestOnlyPolicyNotFoundMeansThePolicyIsGone(t *testing.T) {
	controlURL, _ := newControl(t)
	client, err := NewClient(controlURL, testToken, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.GetPolicy(ctx, "pol_missing"); !isMissing(err, policyNotFound) {
		t.Fatalf("read of a missing policy: %v", err)
	}
	if err := client.DeletePolicy(ctx, "pol_missing"); !isMissing(err, policyNotFound) {
		t.Fatalf("delete of a missing policy: %v", err)
	}

	// A proxy, or a Control Tower without the route, answers 404 without
	// the code: that is not evidence the policy is gone.
	proxy := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(proxy.Close)
	client, err = NewClient(proxy.URL, testToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetPolicy(ctx, "pol_1"); err == nil || isMissing(err, policyNotFound) {
		t.Fatalf("bare 404 taken for a missing policy: %v", err)
	}
}
