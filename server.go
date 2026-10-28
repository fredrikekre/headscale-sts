package main

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	verifier  TokenVerifier
	headscale HeadscaleClient
	replay    *replayGuard
	mux       *http.ServeMux
}

func NewServer(verifier TokenVerifier, headscale HeadscaleClient) *Server {
	s := &Server{
		verifier:  verifier,
		headscale: headscale,
		replay:    newReplayGuard(time.Now()),
		mux:       http.NewServeMux(),
	}
	// Registered both with and without the /sts prefix so that it works
	// whether or not the reverse proxy strips the prefix.
	s.mux.HandleFunc("POST /sts/authkey", s.handleAuthKey)
	s.mux.HandleFunc("POST /authkey", s.handleAuthKey)
	s.mux.HandleFunc("GET /sts/healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok\n"))
}

func (s *Server) handleAuthKey(w http.ResponseWriter, r *http.Request) {
	rawToken, ok := bearerToken(r)
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	claims, trust, err := s.verifier.Verify(r.Context(), rawToken)
	if err != nil {
		log.Printf("token rejected: %v", err)
		http.Error(w, "token verification failed", http.StatusUnauthorized)
		return
	}

	rule := matchRule(trust.Rules, claims)
	if rule == nil {
		log.Printf("no rule matched for issuer=%s sub=%v", trust.Issuer, claims["sub"])
		http.Error(w, "no rule matched", http.StatusForbidden)
		return
	}

	// Each token mints at most one key. The jti is claimed before minting
	// so concurrent requests with the same token cannot both succeed. Keep
	// it claimed on errors too: headscale may have created a key even if
	// its response was lost.
	id, err := s.replay.claim(claims, time.Now())
	if err != nil {
		log.Printf("token rejected: issuer=%s sub=%v jti=%v: %v", trust.Issuer, claims["sub"], claims["jti"], err)
		http.Error(w, "token rejected", http.StatusUnauthorized)
		return
	}

	key, err := s.headscale.CreatePreAuthKey(
		r.Context(), rule.Tags, rule.Key.ephemeral(), rule.Key.reusable(), rule.Key.expiry(),
	)
	if err != nil {
		log.Printf("minting key failed: %v", err)
		http.Error(w, "minting key failed", http.StatusBadGateway)
		return
	}

	log.Printf("minted key: issuer=%s sub=%v jti=%s tags=%s expiry=%s",
		trust.Issuer, claims["sub"], id.jti, strings.Join(rule.Tags, ","), rule.Key.expiry())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(key))
}

func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(auth[len(prefix):]), true
}

// replayGuard rejects tokens that have already been used to mint a key. Used
// tokens, identified by iss and jti (jti is only unique per issuer), are kept in memory until the token expires, which is enough for
// a single instance. The set is lost on restart, so tokens issued before the
// guard was created are rejected as well.
type replayGuard struct {
	started time.Time

	mu   sync.Mutex
	seen map[tokenID]time.Time // -> token expiry
}

type tokenID struct {
	iss, jti string
}

func newReplayGuard(started time.Time) *replayGuard {
	return &replayGuard{started: started, seen: make(map[tokenID]time.Time)}
}

// claim records the token as used and returns its ID, or returns an error if
// the token has no jti, was issued before the guard was created, or has
// already been used.
func (g *replayGuard) claim(claims map[string]any, now time.Time) (tokenID, error) {
	iss, _ := claims["iss"].(string)
	jti, _ := claims["jti"].(string)
	if iss == "" || jti == "" {
		return tokenID{}, errors.New("token has no iss or jti")
	}
	iat, ok := claimTime(claims["iat"])
	if !ok {
		return tokenID{}, errors.New("token has no iat")
	}
	// Keep the full startup time: truncating it would admit tokens used
	// before a restart in the same second.
	if iat.Before(g.started) {
		return tokenID{}, errors.New("token issued before service start")
	}
	exp, ok := claimTime(claims["exp"])
	if !ok {
		return tokenID{}, errors.New("token has no exp")
	}
	id := tokenID{iss: iss, jti: jti}

	g.mu.Lock()
	defer g.mu.Unlock()
	for seen, e := range g.seen {
		if now.After(e) {
			delete(g.seen, seen)
		}
	}
	if _, used := g.seen[id]; used {
		return tokenID{}, errors.New("token already used")
	}
	g.seen[id] = exp
	return id, nil
}

// claimTime parses a NumericDate claim (seconds since the epoch).
func claimTime(v any) (time.Time, bool) {
	sec, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(sec), 0), true
}
