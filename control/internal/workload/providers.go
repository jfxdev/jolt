package workload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const maxProviders = 32
const maxProviderFileBytes = 1 << 20

type providerDocument struct {
	Version   int                  `json:"version"`
	Providers []providerDefinition `json:"providers"`
}

type providerDefinition struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Issuer      string   `json:"issuer,omitempty"`
	Audience    string   `json:"audience"`
	JWKSURL     string   `json:"jwks_url,omitempty"`
	Algorithms  []string `json:"algorithms,omitempty"`
	TrustDomain string   `json:"trust_domain,omitempty"`
	BundleFile  string   `json:"bundle_file,omitempty"`
}

type provider struct {
	definition providerDefinition
	jwt        *JWTValidator
	svid       *SVIDValidator
}

// ProviderSet is immutable after construction; its JWT validators coordinate
// JWKS refresh internally. It does not itself grant access to any account.
type ProviderSet struct{ providers []provider }

// LoadProviders parses a versioned JSON file, resolving SVID bundle paths
// relative to it. No bearer credentials are read or persisted here.
func LoadProviders(filename string) (*ProviderSet, error) {
	data, err := readBoundedFile(filename, maxProviderFileBytes)
	if err != nil || filetypes.ValidateUniqueJSON(data) != nil {
		return nil, ErrInvalid
	}
	var document providerDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.Version != 1 || len(document.Providers) == 0 || len(document.Providers) > maxProviders {
		return nil, ErrInvalid
	}
	result := &ProviderSet{}
	ids, routes := map[string]bool{}, map[string]bool{}
	for _, definition := range document.Providers {
		if !identityField(definition.ID) || len(definition.ID) > 128 || ids[definition.ID] || !identityField(definition.Audience) {
			return nil, ErrInvalid
		}
		ids[definition.ID] = true
		item := provider{definition: definition}
		var route string
		switch definition.Type {
		case "jwt":
			if definition.TrustDomain != "" || definition.BundleFile != "" {
				return nil, ErrInvalid
			}
			item.jwt, err = NewJWTValidator(JWTConfig{ProviderID: definition.ID, Issuer: definition.Issuer, Audience: definition.Audience, JWKSURL: definition.JWKSURL, Algorithms: definition.Algorithms})
			route = "jwt\x00" + definition.Issuer + "\x00" + definition.Audience
		case "jwt_svid":
			if definition.Issuer != "" || definition.JWKSURL != "" || len(definition.Algorithms) != 0 || definition.BundleFile == "" {
				return nil, ErrInvalid
			}
			bundlePath := definition.BundleFile
			if !filepath.IsAbs(bundlePath) {
				bundlePath = filepath.Join(filepath.Dir(filename), bundlePath)
			}
			bundle, readErr := readBoundedFile(bundlePath, maxJWKSBytes)
			if readErr != nil {
				return nil, ErrInvalid
			}
			item.svid, err = NewSVIDValidator(definition.ID, definition.TrustDomain, definition.Audience, bundle)
			if err == nil {
				route = "jwt_svid\x00" + item.svid.trustDomain.String() + "\x00" + definition.Audience
			}
		default:
			return nil, ErrInvalid
		}
		if err != nil || routes[route] {
			return nil, ErrInvalid
		}
		routes[route] = true
		result.providers = append(result.providers, item)
	}
	return result, nil
}

// Verify uses unverified claims solely to pick a single candidate. Ambiguous
// candidates are rejected; the selected validator then verifies the signature
// and all claims before returning an identity suitable for mapping lookup.
func (p *ProviderSet) Verify(ctx context.Context, token string) (Identity, error) {
	if p == nil || ctx.Err() != nil || validateCompactToken(token) != nil {
		return Identity{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	var claims jwt.Claims
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return Identity{}, ErrInvalid
	}
	id, spiffeErr := spiffeid.FromString(claims.Subject)
	selected := -1
	for i, item := range p.providers {
		if !claims.Audience.Contains(item.definition.Audience) {
			continue
		}
		matches := item.jwt != nil && claims.Issuer == item.definition.Issuer || item.svid != nil && spiffeErr == nil && id.TrustDomain() == item.svid.trustDomain
		if !matches {
			continue
		}
		if selected != -1 {
			return Identity{}, ErrInvalid
		}
		selected = i
	}
	if selected == -1 {
		return Identity{}, ErrInvalid
	}
	item := p.providers[selected]
	if item.jwt != nil {
		return item.jwt.Verify(ctx, token)
	}
	return item.svid.Verify(token)
}

func readBoundedFile(filename string, max int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || len(data) == 0 || int64(len(data)) > max {
		return nil, ErrInvalid
	}
	return data, nil
}
