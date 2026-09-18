package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	srv := NewServer(&fakeVerifier{
		claims: map[string]any{"repository": "Org/Repo", "sub": "repo:Org/Repo"},
		trust:  testTrust(),
	}, hs)

	for _, path := range []string{"/sts/authkey", "/authkey"} {
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
	srv := NewServer(&fakeVerifier{err: errors.New("should not be called")}, &fakeHeadscale{})
	w := request(t, srv, http.MethodPost, "/sts/authkey", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlerBadToken(t *testing.T) {
	srv := NewServer(&fakeVerifier{err: errors.New("bad signature")}, &fakeHeadscale{})
	w := request(t, srv, http.MethodPost, "/sts/authkey", "token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "bad signature") {
		t.Error("verification error details must not leak to the client")
	}
}

func TestHandlerNoRuleMatch(t *testing.T) {
	srv := NewServer(&fakeVerifier{
		claims: map[string]any{"repository": "Evil/Repo"},
		trust:  testTrust(),
	}, &fakeHeadscale{key: "k"})
	w := request(t, srv, http.MethodPost, "/sts/authkey", "token")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlerHeadscaleError(t *testing.T) {
	srv := NewServer(&fakeVerifier{
		claims: map[string]any{"repository": "Org/Repo"},
		trust:  testTrust(),
	}, &fakeHeadscale{err: errors.New("api down")})
	w := request(t, srv, http.MethodPost, "/sts/authkey", "token")
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	srv := NewServer(&fakeVerifier{}, &fakeHeadscale{})
	w := request(t, srv, http.MethodGet, "/sts/authkey", "token")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlerHealthz(t *testing.T) {
	srv := NewServer(&fakeVerifier{}, &fakeHeadscale{})
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
			srv := NewServer(verifier, hs)
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
