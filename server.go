package main

import (
	"log"
	"net/http"
	"strings"
)

type Server struct {
	verifier  TokenVerifier
	headscale HeadscaleClient
	mux       *http.ServeMux
}

func NewServer(verifier TokenVerifier, headscale HeadscaleClient) *Server {
	s := &Server{
		verifier:  verifier,
		headscale: headscale,
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

	key, err := s.headscale.CreatePreAuthKey(
		r.Context(), rule.Tags, rule.Key.ephemeral(), rule.Key.reusable(), rule.Key.expiry(),
	)
	if err != nil {
		log.Printf("minting key failed: %v", err)
		http.Error(w, "minting key failed", http.StatusBadGateway)
		return
	}

	log.Printf("minted key: issuer=%s sub=%v tags=%s expiry=%s",
		trust.Issuer, claims["sub"], strings.Join(rule.Tags, ","), rule.Key.expiry())
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
