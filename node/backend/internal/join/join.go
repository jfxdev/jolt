// Package join enrolls a node in the Control Tower's certificate authority with
// a one-use token, in the manner of kubeadm: the token carries the Control
// Tower's address and the SHA-256 of its root, so the node trusts nothing it
// has not checked against that hash.
package join

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/trust"
)

const tokenPrefix = "jolt-join:v1:"

// Token is what the administrator hands to a node.
type Token struct {
	Secret     string
	RootPin    string
	ControlURL string
}

// ParseToken reads "jolt-join:v1:<secret>:<sha256 of the root>:<https URL>".
func ParseToken(value string) (Token, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, tokenPrefix) {
		return Token{}, errors.New("the join token is not in the expected format")
	}
	parts := strings.SplitN(strings.TrimPrefix(value, tokenPrefix), ":", 3)
	if len(parts) != 3 {
		return Token{}, errors.New("the join token is not in the expected format")
	}
	secret, pin, address := parts[0], parts[1], parts[2]
	if len(secret) < 32 || len(secret) > 128 || strings.ContainsAny(secret, " \t\r\n") {
		return Token{}, errors.New("the join token secret is malformed")
	}
	if len(pin) != 64 {
		return Token{}, errors.New("the join token root fingerprint is malformed")
	}
	if _, err := hex.DecodeString(pin); err != nil || pin != strings.ToLower(pin) {
		return Token{}, errors.New("the join token root fingerprint is malformed")
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return Token{}, errors.New("the join token must point at an https address")
	}
	return Token{Secret: secret, RootPin: pin, ControlURL: strings.TrimRight(address, "/")}, nil
}

// Options is what a node brings to its enrollment.
type Options struct {
	Token       Token
	NodeName    string
	NodeID      string
	Fingerprint string
	APIEndpoint string
	Manager     *trust.Manager
	Tokens      trust.TokenStore
	Log         *slog.Logger
	// Deadline bounds the whole attempt; the default is 20 minutes.
	Deadline time.Duration
	// Poll bounds the wait between asks while a person decides.
	PollMin, PollMax time.Duration
}

type enrollRequest struct {
	Secret           string `json:"secret"`
	NodeName         string `json:"node_name"`
	NodeID           string `json:"node_id"`
	NodeFingerprint  string `json:"node_fingerprint"`
	APIEndpoint      string `json:"api_endpoint"`
	CSR              string `json:"csr_pem"`
	OperationalToken string `json:"operational_token"`
}

type enrollResponse struct {
	Status      string          `json:"status"`
	Certificate string          `json:"certificate_pem"`
	Bundle      json.RawMessage `json:"bundle"`
	RequestID   string          `json:"request_id"`
	PollSecret  string          `json:"poll_secret"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Note        string          `json:"note"`
}

// fatal marks an answer that retrying cannot change.
type fatal struct{ error }

// Run enrolls the node, waiting while a person decides if the Control Tower is
// set to ask. On success the node holds its certificate, the first trust
// bundle and an operational token the Control Tower knows.
func Run(ctx context.Context, opts Options) error {
	if opts.Deadline <= 0 {
		opts.Deadline = 20 * time.Minute
	}
	if opts.PollMin <= 0 {
		opts.PollMin = 5 * time.Second
	}
	if opts.PollMax < opts.PollMin {
		opts.PollMax = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Deadline)
	defer cancel()

	client, err := pinnedClient(ctx, opts)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(opts.APIEndpoint)
	if err != nil || endpoint.Hostname() == "" {
		return errors.New("api_public_endpoint is not a valid URL")
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: opts.NodeID}}
	if ip := net.ParseIP(endpoint.Hostname()); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{endpoint.Hostname()}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	operational := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(operational))
	request := enrollRequest{
		Secret: opts.Token.Secret, NodeName: opts.NodeName, NodeID: opts.NodeID, NodeFingerprint: opts.Fingerprint, APIEndpoint: opts.APIEndpoint,
		CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), OperationalToken: operational,
	}

	var answer enrollResponse
	err = retry(ctx, opts, func() error {
		var callErr error
		answer, callErr = post(ctx, client, opts.Token.ControlURL+"/api/v1/control-tower/enroll", request)
		return callErr
	})
	if err != nil {
		return err
	}
	if answer.Status == "pending" {
		opts.Log.Info("enrollment is waiting for a person to approve it in the Control Tower",
			"node_fingerprint", opts.Fingerprint, "request_id", answer.RequestID, "expires_at", answer.ExpiresAt)
		answer, err = wait(ctx, client, opts, answer)
		if err != nil {
			return err
		}
	}
	if answer.Status != "issued" {
		return fmt.Errorf("the Control Tower answered %q", answer.Status)
	}
	bundle, err := trust.ParseBundle(answer.Bundle)
	if err != nil {
		return err
	}
	if err := opts.Manager.Enroll(ctx, opts.Token.RootPin, bundle, answer.Certificate, keyDER, hex.EncodeToString(sum[:])); err != nil {
		return fmt.Errorf("refusing what the Control Tower sent: %w", err)
	}
	return opts.Manager.EnsureOperationalToken(ctx, opts.Tokens)
}

// pinnedClient fetches the root without trusting the connection, accepts it
// only if it has the SHA-256 the token pinned, and returns a client that trusts
// that root and nothing else.
func pinnedClient(ctx context.Context, opts Options) (*http.Client, error) {
	var rootPEM []byte
	err := retry(ctx, opts, func() error {
		insecure := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			// The answer is public and is checked against the pinned hash
			// below; nothing secret is sent on this connection.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402
		}}
		defer insecure.CloseIdleConnections()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.Token.ControlURL+"/.well-known/jolt/ca.pem", nil)
		if err != nil {
			return fatal{err}
		}
		response, err := insecure.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("fetching the root: status %d", response.StatusCode)
		}
		rootPEM, err = io.ReadAll(io.LimitReader(response.Body, 16<<10))
		return err
	})
	if err != nil {
		return nil, err
	}
	root, err := trust.ParseCertificate(rootPEM)
	if err != nil || trust.Fingerprint(root) != opts.Token.RootPin {
		return nil, errors.New("the root the Control Tower presented does not have the fingerprint in the join token; nothing was sent")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, nil
}

func post(ctx context.Context, client *http.Client, address string, body any) (enrollResponse, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return enrollResponse{}, fatal{err}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(encoded))
	if err != nil {
		return enrollResponse{}, fatal{err}
	}
	request.Header.Set("Content-Type", "application/json")
	return exchange(client, request)
}

func exchange(client *http.Client, request *http.Request) (enrollResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return enrollResponse{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	if err != nil {
		return enrollResponse{}, err
	}
	switch {
	case response.StatusCode == http.StatusOK || response.StatusCode == http.StatusAccepted:
		var answer enrollResponse
		if err := json.Unmarshal(data, &answer); err != nil {
			return enrollResponse{}, fatal{fmt.Errorf("the Control Tower's answer is not understood: %w", err)}
		}
		return answer, nil
	case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusGone:
		var answer enrollResponse
		_ = json.Unmarshal(data, &answer)
		if answer.Note != "" {
			return enrollResponse{}, fatal{fmt.Errorf("enrollment was not approved: %s", answer.Note)}
		}
		return enrollResponse{}, fatal{errors.New("enrollment was rejected or expired")}
	case response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
		return enrollResponse{}, fmt.Errorf("the Control Tower answered %d", response.StatusCode)
	default:
		return enrollResponse{}, fatal{fmt.Errorf("the Control Tower refused the enrollment (status %d): %s", response.StatusCode, strings.TrimSpace(string(data)))}
	}
}

func wait(ctx context.Context, client *http.Client, opts Options, pending enrollResponse) (enrollResponse, error) {
	interval := opts.PollMin
	for {
		select {
		case <-ctx.Done():
			return enrollResponse{}, errors.New("gave up waiting for the enrollment to be approved")
		case <-time.After(interval):
		}
		var answer enrollResponse
		err := retry(ctx, opts, func() error {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.Token.ControlURL+"/api/v1/control-tower/enroll/"+url.PathEscape(pending.RequestID), nil)
			if err != nil {
				return fatal{err}
			}
			request.Header.Set("Authorization", "Bearer "+pending.PollSecret)
			answer, err = exchange(client, request)
			return err
		})
		if err != nil {
			return enrollResponse{}, err
		}
		if answer.Status != "pending" {
			return answer, nil
		}
		if interval *= 2; interval > opts.PollMax {
			interval = opts.PollMax
		}
	}
}

// retry repeats a call that failed for a reason time can fix, with a growing
// pause, until the attempt's deadline.
func retry(ctx context.Context, opts Options, call func() error) error {
	pause := 500 * time.Millisecond
	for {
		err := call()
		if err == nil {
			return nil
		}
		var stop fatal
		if errors.As(err, &stop) {
			return stop.error
		}
		if ctx.Err() != nil {
			return fmt.Errorf("the Control Tower could not be reached: %w", err)
		}
		if opts.Log != nil {
			opts.Log.Warn("enrollment will retry", "error", err.Error(), "in", pause.String())
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the Control Tower could not be reached: %w", err)
		case <-time.After(pause):
		}
		if pause *= 2; pause > 15*time.Second {
			pause = 15 * time.Second
		}
	}
}
