// Command fakeissuer is a minimal OIDC issuer for running the integration
// test outside GitHub Actions: it serves a discovery document and JWKS over
// plain HTTP, and freshly signed tokens with the given claims at /token,
// mimicking the GitHub Actions token endpoint (GET /token?audience=...
// responds with {"value": "<token>"}). Tokens are minted on request since
// headscale-sts rejects tokens issued before it started.
//
//	go run ./integration/fakeissuer -claims '{"repository":"fredrikekre/headscale-sts"}' &
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:19999", "address to listen on; the issuer is http://<listen>")
	claimsJSON := flag.String("claims", "{}", "extra token claims as a JSON object")
	flag.Parse()
	issuer := "http://" + *listen

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		log.Fatal(err)
	}

	var extra map[string]any
	if err := json.Unmarshal([]byte(*claimsJSON), &extra); err != nil {
		log.Fatalf("parsing -claims: %v", err)
	}
	sign := func(aud string) string {
		claims := map[string]any{
			"iss": issuer,
			"aud": aud,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"jti": rand.Text(),
		}
		for k, v := range extra {
			claims[k] = v
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			log.Fatal(err)
		}
		jws, err := signer.Sign(payload)
		if err != nil {
			log.Fatal(err)
		}
		raw, err := jws.CompactSerialize()
		if err != nil {
			log.Fatal(err)
		}
		return raw
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": sign(r.URL.Query().Get("audience"))})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}},
		})
	})
	log.Printf("fakeissuer %s serving; tokens at %s/token", issuer, issuer)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
