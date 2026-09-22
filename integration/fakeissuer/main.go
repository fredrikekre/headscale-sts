// Command fakeissuer is a minimal OIDC issuer for running the integration
// test outside GitHub Actions: it serves a discovery document and JWKS over
// plain HTTP and writes signed tokens for the given claims to -token-file
// (and a wrong-audience variant to -token-file plus the ".wrongaud" suffix).
//
//	go run ./integration/fakeissuer -audience https://headscale-sts.invalid/sts \
//	    -claims '{"repository":"fredrikekre/headscale-sts"}' -token-file /tmp/token &
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:19999", "address to listen on; the issuer is http://<listen>")
	audience := flag.String("audience", "", "audience for the signed tokens")
	claimsJSON := flag.String("claims", "{}", "extra token claims as a JSON object")
	tokenFile := flag.String("token-file", "", "file to write the signed token to")
	flag.Parse()
	if *audience == "" || *tokenFile == "" {
		log.Fatal("-audience and -token-file are required")
	}
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
	sign := func(aud string) []byte {
		claims := map[string]any{
			"iss": issuer,
			"aud": aud,
			"iat": time.Now().Add(-time.Minute).Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
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
		return []byte(raw)
	}
	if err := os.WriteFile(*tokenFile, sign(*audience), 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*tokenFile+".wrongaud", sign(*audience+"-wrong"), 0o600); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}},
		})
	})
	log.Printf("fakeissuer %s serving; tokens written to %s", issuer, *tokenFile)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
