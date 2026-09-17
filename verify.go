package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// TokenVerifier verifies a raw bearer token against the configured trusts
// and returns the token claims together with the trust that verified it.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (map[string]any, *Trust, error)
}

// oidcVerifier verifies tokens against the trusts using OIDC discovery.
// Providers are initialized lazily on first use so that the service starts
// (and can be tested) without reaching the issuers.
type oidcVerifier struct {
	trusts []Trust

	mu        sync.Mutex
	providers map[string]*oidc.Provider
}

func NewOIDCVerifier(trusts []Trust) TokenVerifier {
	return &oidcVerifier{
		trusts:    trusts,
		providers: make(map[string]*oidc.Provider),
	}
}

// unverifiedIssuer extracts the iss claim without verifying the token. It
// is only used to select which trusts to verify the token against; the
// issuer is verified cryptographically by the OIDC verifier afterwards.
func unverifiedIssuer(rawToken string) (string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("malformed token payload: %w", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("malformed token claims: %w", err)
	}
	if claims.Issuer == "" {
		return "", errors.New("token has no issuer")
	}
	return claims.Issuer, nil
}

func (v *oidcVerifier) provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if p, ok := v.providers[issuer]; ok {
		return p, nil
	}
	// The provider (and its remote key set) keeps using this context's
	// client for later JWKS refreshes, so use a long-lived context with a
	// timeout-limited client rather than the request context.
	pctx := oidc.ClientContext(context.Background(), &http.Client{Timeout: 10 * time.Second})
	p, err := oidc.NewProvider(pctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", issuer, err)
	}
	v.providers[issuer] = p
	return p, nil
}

func (v *oidcVerifier) Verify(ctx context.Context, rawToken string) (map[string]any, *Trust, error) {
	issuer, err := unverifiedIssuer(rawToken)
	if err != nil {
		return nil, nil, err
	}
	var errs []error
	for i := range v.trusts {
		trust := &v.trusts[i]
		if trust.Issuer != issuer {
			continue
		}
		provider, err := v.provider(ctx, trust.Issuer)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		verifier := provider.Verifier(&oidc.Config{ClientID: trust.Audience})
		idToken, err := verifier.Verify(ctx, rawToken)
		if err != nil {
			errs = append(errs, fmt.Errorf("verifying against %s (aud %s): %w", trust.Issuer, trust.Audience, err))
			continue
		}
		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			return nil, nil, fmt.Errorf("decoding claims: %w", err)
		}
		return claims, trust, nil
	}
	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}
	return nil, nil, fmt.Errorf("no trust configured for issuer %s", issuer)
}

// matchRule returns the first rule whose match claims all equal the
// corresponding token claims, or nil if no rule matches.
func matchRule(rules []Rule, claims map[string]any) *Rule {
	for i := range rules {
		rule := &rules[i]
		if ruleMatches(rule, claims) {
			return rule
		}
	}
	return nil
}

func ruleMatches(rule *Rule, claims map[string]any) bool {
	for claim, want := range rule.Match {
		got, ok := claims[claim]
		if !ok {
			return false
		}
		if claimString(got) != want {
			return false
		}
	}
	return true
}

// claimString renders a scalar claim value for comparison. Non-scalar
// claims (arrays, objects) never match.
func claimString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case bool:
		return fmt.Sprintf("%t", val)
	case float64:
		// JSON numbers; render integers without decimals.
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%v", val)
	case json.Number:
		return val.String()
	default:
		return ""
	}
}
