// headscale-sts is a small security token service (STS) that federates
// workload identities into headscale preauth keys: a workload (e.g. a GitHub
// Actions job) presents the OIDC token issued by its platform, headscale-sts
// verifies it against the configured trusted issuers and claim rules, and
// responds with a freshly minted (typically single-use, short-lived, tagged)
// headscale preauth key.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	configPath := flag.String("config", "/etc/headscale-sts/config.yaml", "path to the configuration file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	srv := NewServer(NewOIDCVerifier(cfg.Trusts), NewHeadscaleClient(cfg.Headscale))
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Printf("headscale-sts listening on %s (%d trust(s) configured)", cfg.Listen, len(cfg.Trusts))
	log.Fatal(httpServer.ListenAndServe())
}
