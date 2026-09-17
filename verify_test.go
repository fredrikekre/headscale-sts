package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeIssuer is an OIDC issuer served from httptest: discovery document,
// JWKS, and token signing.
type fakeIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key, signer: signer}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.server.URL,
			"jwks_uri":                              f.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}},
		})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// sign creates a signed token with the given claims, filling in iss/exp/iat
// unless already present.
func (f *fakeIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	full := map[string]any{
		"iss": f.server.URL,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		full[k] = v
	}
	payload, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := f.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func githubClaims(audience string) map[string]any {
	return map[string]any{
		"aud":        audience,
		"sub":        "repo:Org/Repo:ref:refs/heads/master",
		"repository": "Org/Repo",
		"ref":        "refs/heads/master",
	}
}

func TestVerifyValidToken(t *testing.T) {
	issuer := newFakeIssuer(t)
	const audience = "https://headscale.example.org/sts"
	v := NewOIDCVerifier([]Trust{{
		Issuer:   issuer.server.URL,
		Audience: audience,
		Rules:    []Rule{{Match: map[string]string{"repository": "Org/Repo"}, Tags: []string{"tag:ci"}}},
	}})

	claims, trust, err := v.Verify(context.Background(), issuer.sign(t, githubClaims(audience)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if trust.Issuer != issuer.server.URL {
		t.Errorf("trust.Issuer = %q", trust.Issuer)
	}
	if claims["repository"] != "Org/Repo" {
		t.Errorf("claims = %v", claims)
	}
}

func TestVerifyRejections(t *testing.T) {
	issuer := newFakeIssuer(t)
	other := newFakeIssuer(t)
	const audience = "https://headscale.example.org/sts"
	v := NewOIDCVerifier([]Trust{{
		Issuer:   issuer.server.URL,
		Audience: audience,
		Rules:    []Rule{{Match: map[string]string{"repository": "Org/Repo"}, Tags: []string{"tag:ci"}}},
	}})
	ctx := context.Background()

	t.Run("wrong audience", func(t *testing.T) {
		token := issuer.sign(t, githubClaims("https://something-else.example.org"))
		if _, _, err := v.Verify(ctx, token); err == nil {
			t.Fatal("expected audience error")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		claims := githubClaims(audience)
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		if _, _, err := v.Verify(ctx, issuer.sign(t, claims)); err == nil {
			t.Fatal("expected expiry error")
		}
	})

	t.Run("untrusted issuer", func(t *testing.T) {
		claims := githubClaims(audience)
		claims["iss"] = other.server.URL
		if _, _, err := v.Verify(ctx, other.sign(t, claims)); err == nil {
			t.Fatal("expected untrusted issuer error")
		}
	})

	t.Run("wrong signing key", func(t *testing.T) {
		// Token claims issuer.server.URL as iss but is signed by other's key.
		claims := githubClaims(audience)
		claims["iss"] = issuer.server.URL
		if _, _, err := v.Verify(ctx, other.sign(t, claims)); err == nil {
			t.Fatal("expected signature error")
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		if _, _, err := v.Verify(ctx, "not-a-token"); err == nil {
			t.Fatal("expected parse error")
		}
	})
}

func TestMatchRule(t *testing.T) {
	rules := []Rule{
		{Match: map[string]string{"repository": "Org/Repo", "ref": "refs/heads/master"}, Tags: []string{"tag:master"}},
		{Match: map[string]string{"repository": "Org/Repo"}, Tags: []string{"tag:any-ref"}},
	}
	cases := []struct {
		name     string
		claims   map[string]any
		wantTags string
	}{
		{"first rule wins", map[string]any{"repository": "Org/Repo", "ref": "refs/heads/master"}, "tag:master"},
		{"fallthrough to second", map[string]any{"repository": "Org/Repo", "ref": "refs/heads/dev"}, "tag:any-ref"},
		{"no match", map[string]any{"repository": "Other/Repo"}, ""},
		{"missing claim", map[string]any{"ref": "refs/heads/master"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := matchRule(rules, tc.claims)
			if tc.wantTags == "" {
				if rule != nil {
					t.Fatalf("expected no match, got %v", rule.Tags)
				}
				return
			}
			if rule == nil {
				t.Fatal("expected match, got nil")
			}
			if rule.Tags[0] != tc.wantTags {
				t.Errorf("matched %v, want %v", rule.Tags[0], tc.wantTags)
			}
		})
	}
}

func TestClaimStringScalars(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"str", "str"},
		{true, "true"},
		{float64(42), "42"},
		{float64(1.5), "1.5"},
		{json.Number("7"), "7"},
		{[]any{"a"}, ""},       // arrays never match
		{map[string]any{}, ""}, // objects never match
		{nil, ""},              // null never matches
	}
	for _, tc := range cases {
		if got := claimString(tc.in); got != tc.want {
			t.Errorf("claimString(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnverifiedIssuer(t *testing.T) {
	issuer := newFakeIssuer(t)
	token := issuer.sign(t, map[string]any{"aud": "a"})
	iss, err := unverifiedIssuer(token)
	if err != nil {
		t.Fatal(err)
	}
	if iss != issuer.server.URL {
		t.Errorf("issuer = %q, want %q", iss, issuer.server.URL)
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", fmt.Sprintf("a.%s.c", "e30")} { // e30 = {}
		if _, err := unverifiedIssuer(bad); err == nil {
			t.Errorf("unverifiedIssuer(%q): expected error", bad)
		}
	}
}
