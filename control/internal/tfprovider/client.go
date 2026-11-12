package tfprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
)

const maxResponseBytes = 4 << 20

// Policy is a Control Tower RBAC policy as the API returns it.
type Policy struct {
	ID          string      `json:"policy_id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Rules       []rbac.Rule `json:"rules"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// Node is a node registered in the Control Tower, as the API returns it.
// State and LastSeenAt come from a probe the Control Tower makes on each list.
type Node struct {
	ID            string             `json:"node_id"`
	Name          string             `json:"name"`
	Endpoint      string             `json:"endpoint"`
	State         string             `json:"state"`
	Configuration *NodeConfiguration `json:"configuration,omitempty"`
	LastSeenAt    *time.Time         `json:"last_seen_at,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

// NodeConfiguration is how the node's mounts and grants are managed.
type NodeConfiguration struct {
	Source        string `json:"source"`
	ApplyMode     string `json:"apply_mode"`
	MountsMutable bool   `json:"mounts_mutable"`
	GrantsMutable bool   `json:"grants_mutable"`
}

// PolicyInput is the body of a policy create or update.
type PolicyInput struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Rules       []rbac.Rule `json:"rules"`
}

// APIError keeps the status, code and message of a refused call, and the
// correlation id that finds its decision in the audit log.
type APIError struct {
	Status        int
	Code          string
	Message       string
	CorrelationID string
}

func (e *APIError) Error() string {
	text := fmt.Sprintf("Control Tower answered %d", e.Status)
	if e.Code != "" {
		text += " " + e.Code
	}
	if e.Message != "" {
		text += ": " + e.Message
	}
	if e.CorrelationID != "" {
		text += " (correlation_id " + e.CorrelationID + ")"
	}
	return text
}

func isStatus(err error, status int) bool {
	var failure *APIError
	return errors.As(err, &failure) && failure.Status == status
}

// isMissing reports a 404 that names the missing object. A 404 without the
// code, from a proxy or a route the Control Tower lacks, says nothing about
// the object and must not be taken for its absence.
func isMissing(err error, code string) bool {
	var failure *APIError
	return errors.As(err, &failure) && failure.Status == http.StatusNotFound && failure.Code == code
}

// Client calls the Control Tower API with a service account token.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// NewClient refuses credentials in URLs and plaintext connections outside
// loopback. Without a CA file the system's trust is used; with one, only the
// roots in it.
func NewClient(rawURL, token, caFile string) (*Client, error) {
	base, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || base == nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return nil, errors.New("control_url must be a scheme and host, without credentials, path or query")
	}
	host := base.Hostname()
	ip := net.ParseIP(host)
	if base.Scheme != "https" && !(base.Scheme == "http" && (strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("control_url must use HTTPS outside loopback")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("token is empty")
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file unavailable: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("ca_file holds no PEM certificate")
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
		client.Transport = transport
	}
	base.Path = ""
	return &Client{base: base, token: strings.TrimSpace(token), http: client}, nil
}

func (c *Client) GetPolicy(ctx context.Context, id string) (Policy, error) {
	var policy Policy
	err := c.do(ctx, http.MethodGet, "/api/v1/control-tower/policies/"+url.PathEscape(id), nil, nil, &policy)
	return policy, err
}

// FindPolicyByName returns the policy with exactly this name.
func (c *Client) FindPolicyByName(ctx context.Context, name string) (Policy, error) {
	var page struct {
		Items []Policy `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/control-tower/policies", url.Values{"name": {name}}, nil, &page); err != nil {
		return Policy{}, err
	}
	for _, policy := range page.Items {
		if policy.Name == name {
			return policy, nil
		}
	}
	return Policy{}, &APIError{Status: http.StatusNotFound, Code: "policy_not_found", Message: "no policy named " + name}
}

// ListNodes returns the nodes this token may list: those in one of its
// access groups that a policy grants list on nodes/<id>.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var page struct {
		Items []Node `json:"items"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/control-tower/nodes", nil, nil, &page)
	return page.Items, err
}

func (c *Client) CreatePolicy(ctx context.Context, input PolicyInput) (Policy, error) {
	var policy Policy
	err := c.do(ctx, http.MethodPost, "/api/v1/control-tower/policies", nil, input, &policy)
	return policy, err
}

func (c *Client) UpdatePolicy(ctx context.Context, id string, input PolicyInput) (Policy, error) {
	var policy Policy
	err := c.do(ctx, http.MethodPatch, "/api/v1/control-tower/policies/"+url.PathEscape(id), nil, input, &policy)
	return policy, err
}

func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/control-tower/policies/"+url.PathEscape(id), nil, nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	target := *c.base
	target.Path = path
	target.RawQuery = query.Encode()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return errors.New("could not encode the request body")
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return errors.New("could not create Control Tower request")
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("X-Correlation-ID", correlationID())
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("Control Tower request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return errors.New("Control Tower response unavailable or too large")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return refusal(response, data)
	}
	if out == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("invalid Control Tower response")
	}
	return nil
}

func refusal(response *http.Response, data []byte) error {
	failure := &APIError{Status: response.StatusCode, CorrelationID: response.Header.Get("X-Correlation-ID")}
	var payload struct {
		Error struct {
			Code          string `json:"code"`
			Message       string `json:"message"`
			CorrelationID string `json:"correlation_id"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &payload) == nil {
		failure.Code = payload.Error.Code
		failure.Message = payload.Error.Message
		if payload.Error.CorrelationID != "" {
			failure.CorrelationID = payload.Error.CorrelationID
		}
	}
	return failure
}

func correlationID() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return "tf_" + hex.EncodeToString(value)
}
