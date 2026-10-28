package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeVerifier struct {
	claims map[string]any
	trust  *Trust
	err    error
}

func (f *fakeVerifier) Verify(ctx context.Context, rawToken string) (map[string]any, *Trust, error) {
	return f.claims, f.trust, f.err
}

type fakeHeadscale struct {
	key  string
	err  error
	tags []string
}

func (f *fakeHeadscale) CreatePreAuthKey(ctx context.Context, tags []string, ephemeral, reusable bool, expiry time.Duration) (string, error) {
	f.tags = tags
	return f.key, f.err
}

func testTrust() *Trust {
	return &Trust{
		Issuer:   "https://issuer.example.org",
		Audience: "aud",
		Rules: []Rule{{
			Match: map[string]string{"repository": "Org/Repo"},
			Tags:  []string{"tag:logsync"},
		}},
	}
}

// tokenClaims returns claims for a fresh, unused token with the given extra
// claims.
func tokenClaims(extra map[string]any) map[string]any {
	claims := map[string]any{
		"iss": testTrust().Issuer,
		"jti": rand.Text(),
		"iat": float64(time.Now().Unix()),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return claims
}

// Most handler tests exercise tokens issued after startup without waiting for
// the next whole second. Startup boundary behavior is tested separately below.
func newTestServer(verifier TokenVerifier, headscale HeadscaleClient) *Server {
	srv := NewServer(verifier, headscale)
	srv.replay.started = time.Now().Add(-time.Second)
	return srv
}

func request(t *testing.T, srv *Server, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestHandlerSuccess(t *testing.T) {
	hs := &fakeHeadscale{key: "hskey-auth-xyz"}
	verifier := &fakeVerifier{trust: testTrust()}
	srv := newTestServer(verifier, hs)

	for _, path := range []string{"/sts/authkey", "/authkey"} {
		verifier.claims = tokenClaims(map[string]any{"repository": "Org/Repo", "sub": "repo:Org/Repo"})
		w := request(t, srv, http.MethodPost, path, "token")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, body %q", path, w.Code, w.Body)
		}
		if body := w.Body.String(); body != "hskey-auth-xyz" {
			t.Errorf("%s: body = %q", path, body)
		}
	}
	if hs.tags[0] != "tag:logsync" {
		t.Errorf("minted with tags %v", hs.tags)
	}
}

func TestHandlerMissingToken(t *testing.T) {
	srv := newTestServer(&fakeVerifier{err: errors.New("should not be called")}, &fakeHeadscale{})
	w := request(t, srv, http.MethodPost, "/sts/authkey", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlerBadToken(t *testing.T) {
	srv := newTestServer(&fakeVerifier{err: errors.New("bad signature")}, &fakeHeadscale{})
	w := request(t, srv, http.MethodPost, "/sts/authkey", "token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "bad signature") {
		t.Error("verification error details must not leak to the client")
	}
}

func TestHandlerNoRuleMatch(t *testing.T) {
	srv := newTestServer(&fakeVerifier{
		claims: tokenClaims(map[string]any{"repository": "Evil/Repo"}),
		trust:  testTrust(),
	}, &fakeHeadscale{key: "k"})
	w := request(t, srv, http.MethodPost, "/sts/authkey", "token")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlerHeadscaleError(t *testing.T) {
	hs := &fakeHeadscale{err: errors.New("api down")}
	srv := newTestServer(&fakeVerifier{
		claims: tokenClaims(map[string]any{"repository": "Org/Repo"}),
		trust:  testTrust(),
	}, hs)
	w := request(t, srv, http.MethodPost, "/sts/authkey", "token")
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d", w.Code)
	}

	// An error may arrive after headscale created the key, so retain the claim.
	hs.err, hs.key = nil, "key"
	w = request(t, srv, http.MethodPost, "/sts/authkey", "token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("retry status = %d", w.Code)
	}
}

func TestHandlerRetainsTokenAfterUpstreamError(t *testing.T) {
	for _, failure := range []string{"truncated response", "invalid JSON", "missing key", "HTTP error"} {
		t.Run(failure, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) > 1 {
					io.WriteString(w, `{"preAuthKey":{"key":"duplicate-key"}}`)
					return
				}
				// Simulate errors after the upstream may have created a key.
				switch failure {
				case "truncated response":
					w.Header().Set("Content-Length", "100")
					io.WriteString(w, "{")
				case "invalid JSON":
					io.WriteString(w, "{")
				case "missing key":
					io.WriteString(w, `{"preAuthKey":{}}`)
				case "HTTP error":
					http.Error(w, "upstream response lost", http.StatusBadGateway)
				}
			}))
			defer upstream.Close()
			verifier := &fakeVerifier{
				claims: tokenClaims(map[string]any{"repository": "Org/Repo"}),
				trust:  testTrust(),
			}
			srv := newTestServer(verifier, NewHeadscaleClient(HeadscaleConfig{URL: upstream.URL}))
			if w := request(t, srv, http.MethodPost, "/authkey", "token"); w.Code != http.StatusBadGateway {
				t.Fatalf("first attempt: status = %d", w.Code)
			}
			if w := request(t, srv, http.MethodPost, "/authkey", "token"); w.Code != http.StatusUnauthorized {
				t.Fatalf("retry: status = %d", w.Code)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("upstream requests = %d, want 1", got)
			}
			// A fresh token can still mint a key.
			verifier.claims = tokenClaims(map[string]any{"repository": "Org/Repo"})
			if w := request(t, srv, http.MethodPost, "/authkey", "fresh-token"); w.Code != http.StatusOK {
				t.Fatalf("fresh token: status = %d", w.Code)
			}
		})
	}
}

func TestHandlerReplay(t *testing.T) {
	verifier := &fakeVerifier{
		claims: tokenClaims(map[string]any{"repository": "Org/Repo"}),
		trust:  testTrust(),
	}
	srv := newTestServer(verifier, &fakeHeadscale{key: "key"})
	if w := request(t, srv, http.MethodPost, "/sts/authkey", "token"); w.Code != http.StatusOK {
		t.Fatalf("first use: status = %d", w.Code)
	}
	if w := request(t, srv, http.MethodPost, "/sts/authkey", "token"); w.Code != http.StatusUnauthorized {
		t.Errorf("replay: status = %d", w.Code)
	}

	// A token that did not match a rule does not use up its jti.
	verifier.claims = tokenClaims(map[string]any{"repository": "Evil/Repo"})
	if w := request(t, srv, http.MethodPost, "/sts/authkey", "token"); w.Code != http.StatusForbidden {
		t.Fatalf("no rule: status = %d", w.Code)
	}
	verifier.claims["repository"] = "Org/Repo"
	if w := request(t, srv, http.MethodPost, "/sts/authkey", "token"); w.Code != http.StatusOK {
		t.Errorf("after 403: status = %d", w.Code)
	}

	cases := map[string]func(map[string]any){
		"no iss":              func(c map[string]any) { delete(c, "iss") },
		"no jti":              func(c map[string]any) { delete(c, "jti") },
		"empty jti":           func(c map[string]any) { c["jti"] = "" },
		"no iat":              func(c map[string]any) { delete(c, "iat") },
		"no exp":              func(c map[string]any) { delete(c, "exp") },
		"issued before start": func(c map[string]any) { c["iat"] = float64(time.Now().Add(-time.Minute).Unix()) },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			verifier.claims = tokenClaims(map[string]any{"repository": "Org/Repo"})
			modify(verifier.claims)
			if w := request(t, srv, http.MethodPost, "/sts/authkey", "token"); w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d", w.Code)
			}
		})
	}
}

func TestReplayGuard(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	g := newReplayGuard(start)
	claims := func(iss, jti string, exp time.Duration) map[string]any {
		return map[string]any{"iss": iss, "jti": jti, "iat": float64(start.Unix()), "exp": float64(start.Add(exp).Unix())}
	}
	if _, err := g.claim(claims("https://a", "1", time.Minute), start); err != nil {
		t.Fatal(err)
	}
	if _, err := g.claim(claims("https://a", "1", time.Minute), start.Add(30*time.Second)); err == nil {
		t.Error("replay before expiry accepted")
	}
	// jti is only unique per issuer.
	if _, err := g.claim(claims("https://b", "1", time.Minute), start); err != nil {
		t.Errorf("same jti from another issuer: %v", err)
	}
	// Expired entries are pruned (the verifier rejects the expired token).
	g.claim(claims("https://a", "2", time.Hour), start.Add(2*time.Minute))
	if _, ok := g.seen[tokenID{iss: "https://a", jti: "1"}]; ok {
		t.Error("expired token not pruned")
	}
}

func TestReplayGuardRestartBoundary(t *testing.T) {
	issued := time.Unix(1_000_000, 0)
	claims := map[string]any{
		"iss": "https://issuer.example.org", "jti": "same-token",
		"iat": float64(issued.Unix()), "exp": float64(issued.Add(time.Hour).Unix()),
	}
	original := newReplayGuard(issued.Add(-time.Second))
	if _, err := original.claim(claims, issued.Add(100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	// A restart later in the issue second must not allow the token again.
	restarted := newReplayGuard(issued.Add(200 * time.Millisecond))
	if _, err := restarted.claim(claims, issued.Add(300*time.Millisecond)); err == nil {
		t.Fatal("token issued in restart second was accepted")
	}
	claims["iat"] = float64(issued.Add(time.Second).Unix())
	if _, err := restarted.claim(claims, issued.Add(time.Second)); err != nil {
		t.Fatalf("token issued in next second rejected: %v", err)
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	srv := newTestServer(&fakeVerifier{}, &fakeHeadscale{})
	w := request(t, srv, http.MethodGet, "/sts/authkey", "token")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlerHealthz(t *testing.T) {
	srv := newTestServer(&fakeVerifier{}, &fakeHeadscale{})
	for _, path := range []string{"/sts/healthz", "/healthz"} {
		w := request(t, srv, http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d", path, w.Code)
		}
	}
}

func TestHeadscaleClient(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/preauthkey" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		json.NewEncoder(w).Encode(map[string]any{"preAuthKey": map[string]any{"key": "hskey-auth-abc"}})
	}))
	defer ts.Close()

	c := NewHeadscaleClient(HeadscaleConfig{URL: ts.URL, APIKey: "apikey"})
	key, err := c.CreatePreAuthKey(context.Background(), []string{"tag:logsync"}, true, false, 5*time.Minute)
	if err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	if key != "hskey-auth-abc" {
		t.Errorf("key = %q", key)
	}
	if gotAuth != "Bearer apikey" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody["ephemeral"] != true || gotBody["reusable"] != false {
		t.Errorf("body = %v", gotBody)
	}
	tags, _ := gotBody["aclTags"].([]any)
	if len(tags) != 1 || tags[0] != "tag:logsync" {
		t.Errorf("aclTags = %v", gotBody["aclTags"])
	}
	exp, err := time.Parse(time.RFC3339, gotBody["expiration"].(string))
	if err != nil {
		t.Fatalf("expiration not RFC3339: %v", err)
	}
	if d := time.Until(exp); d < 4*time.Minute || d > 6*time.Minute {
		t.Errorf("expiration %v not ~5m away", d)
	}
}

func TestHeadscaleClientErrors(t *testing.T) {
	t.Run("http error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "denied", http.StatusUnauthorized)
		}))
		defer ts.Close()
		c := NewHeadscaleClient(HeadscaleConfig{URL: ts.URL, APIKey: "bad"})
		if _, err := c.CreatePreAuthKey(context.Background(), []string{"tag:x"}, true, false, time.Minute); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("empty key in response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"preAuthKey": map[string]any{}})
		}))
		defer ts.Close()
		c := NewHeadscaleClient(HeadscaleConfig{URL: ts.URL, APIKey: "k"})
		if _, err := c.CreatePreAuthKey(context.Background(), []string{"tag:x"}, true, false, time.Minute); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestHandlerMultipleTrusts(t *testing.T) {
	issuer := newFakeIssuer(t)
	other := newFakeIssuer(t)
	rule := func(repo, tag string) []Rule {
		return []Rule{{Match: map[string]string{"repository": repo}, Tags: []string{tag}}}
	}
	trusts := []Trust{
		{Issuer: issuer.server.URL, Audience: "aud", Rules: rule("First/Repo", "tag:first")},
		{Issuer: issuer.server.URL, Audience: "aud", Rules: rule("Org/Repo", "tag:second")},
		{Issuer: issuer.server.URL, Audience: "other-aud", Rules: rule("Other/Repo", "tag:other")},
		{Issuer: other.server.URL, Audience: "aud", Rules: rule("Foreign/Repo", "tag:foreign")},
		{Issuer: issuer.server.URL, Audience: "aud", Rules: rule("Org/Repo", "tag:shadowed")},
	}
	verifier := NewOIDCVerifier(trusts)
	cases := []struct {
		name, repo string
		audience   any
		status     int
		tag        string
	}{
		{"first trust", "First/Repo", "aud", http.StatusOK, "tag:first"},
		{"later trust and first matching rule wins", "Org/Repo", "aud", http.StatusOK, "tag:second"},
		{"later audience", "Other/Repo", "other-aud", http.StatusOK, "tag:other"},
		{"multiple audiences", "Other/Repo", []string{"aud", "other-aud"}, http.StatusOK, "tag:other"},
		{"no rule", "Unknown/Repo", "aud", http.StatusForbidden, ""},
		{"wrong audience cannot authorize", "Other/Repo", "aud", http.StatusForbidden, ""},
		{"wrong issuer cannot authorize", "Foreign/Repo", "aud", http.StatusForbidden, ""},
		{"no verified trust", "Org/Repo", "invalid", http.StatusUnauthorized, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := &fakeHeadscale{key: "key"}
			srv := newTestServer(verifier, hs)
			token := issuer.sign(t, map[string]any{"aud": tc.audience, "repository": tc.repo})
			w := request(t, srv, http.MethodPost, "/authkey", token)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body)
			}
			if tc.tag == "" {
				if len(hs.tags) != 0 {
					t.Fatalf("unexpected key minted: %v", hs.tags)
				}
			} else if len(hs.tags) != 1 || hs.tags[0] != tc.tag {
				t.Fatalf("tags = %v, want %s", hs.tags, tc.tag)
			}
		})
	}
}
