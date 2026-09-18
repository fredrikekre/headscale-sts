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
// and returns the first verified trust with a matching rule. If no rule
// matches, it returns the first verified trust so the handler can return 403.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (map[string]any, *Trust, error)
}

// oidcVerifier verifies tokens against the trusts using OIDC discovery.
// Providers are initialized lazily on first use so that the service starts
// (and can be tested) without reaching the issuers.
type oidcVerifier struct {
	trusts []Trust

	mu        sync.Mutex
	providers map[string]*providerEntry
}

func NewOIDCVerifier(trusts []Trust) TokenVerifier {
	return &oidcVerifier{
		trusts:    trusts,
		providers: make(map[string]*providerEntry),
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

// A closed done channel publishes the discovery result to all waiters.
type providerEntry struct {
	done       chan struct{}
	provider   *oidc.Provider
	err        error
	retryAfter time.Time
}

const discoveryRetryDelay = 10 * time.Second

func (v *oidcVerifier) provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	entry := v.providers[issuer]
	if entry != nil {
		select {
		case <-entry.done:
			if entry.err != nil && !time.Now().Before(entry.retryAfter) {
				entry = nil
			}
		default:
		}
	}
	if entry == nil {
		entry = &providerEntry{done: make(chan struct{})}
		v.providers[issuer] = entry
		go func() {
			// Discovery and subsequent JWKS refreshes share a long-lived context
			// with a bounded HTTP client, independent of any one caller.
			pctx := oidc.ClientContext(context.Background(), &http.Client{Timeout: 10 * time.Second})
			entry.provider, entry.err = oidc.NewProvider(pctx, issuer)
			if entry.err != nil {
				entry.err = fmt.Errorf("OIDC discovery for %s: %w", issuer, entry.err)
				entry.retryAfter = time.Now().Add(discoveryRetryDelay)
			}
			close(entry.done)
		}()
	}
	v.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-entry.done:
		return entry.provider, entry.err
	}
}

func (v *oidcVerifier) Verify(ctx context.Context, rawToken string) (map[string]any, *Trust, error) {
	issuer, err := unverifiedIssuer(rawToken)
	if err != nil {
		return nil, nil, err
	}
	var errs []error
	var firstClaims map[string]any
	var firstTrust *Trust
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
		if matchRule(trust.Rules, claims) != nil {
			return claims, trust, nil
		}
		if firstTrust == nil {
			firstClaims, firstTrust = claims, trust
		}
	}
	if firstTrust != nil {
		return firstClaims, firstTrust, nil
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
		if value, scalar := claimString(got); !scalar || value != want {
			return false
		}
	}
	return true
}

// claimString renders a scalar claim value for comparison. Non-scalar
// claims (arrays, objects) never match.
func claimString(v any) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case bool:
		return fmt.Sprintf("%t", val), true
	case float64:
		// JSON numbers; render integers without decimals.
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val)), true
		}
		return fmt.Sprintf("%v", val), true
	case json.Number:
		return val.String(), true
	default:
		return "", false
	}
}
