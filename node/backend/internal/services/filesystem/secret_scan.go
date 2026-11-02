package filesystem

import (
	"errors"
	"io"
	"os"
	"regexp"
)

var ErrSecretDetected = errors.New("secret detected")

// SecretError carries only a bounded classifier, never the matched bytes.
type SecretError struct{ Kind string }

func (e *SecretError) Error() string { return ErrSecretDetected.Error() }
func (e *SecretError) Unwrap() error { return ErrSecretDetected }

var secretPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"private_key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)},
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
	{"github_token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{"credential_assignment", regexp.MustCompile(`(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|token)\s*[:=]\s*["']?[^\s"']{8,}`)},
}

// ScanSecretPrefix reads from offset zero without disturbing the file position.
func ScanSecretPrefix(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return ErrInvalid
	}
	buffer := make([]byte, 64<<10)
	n, err := file.ReadAt(buffer, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	for _, pattern := range secretPatterns {
		if pattern.re.Match(buffer[:n]) {
			return &SecretError{Kind: pattern.kind}
		}
	}
	return nil
}
