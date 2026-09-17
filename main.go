// headscale-sts is a small security token service (STS) that federates
// workload identities into headscale preauth keys: a workload (e.g. a GitHub
// Actions job) presents the OIDC token issued by its platform, headscale-sts
// verifies it against the configured trusted issuers and claim rules, and
// responds with a freshly minted (typically single-use, short-lived, tagged)
// headscale preauth key.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/headscale-sts/config.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

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
	log.Printf("headscale-sts %s listening on %s (%d trust(s) configured)", version, cfg.Listen, len(cfg.Trusts))
	log.Fatal(httpServer.ListenAndServe())
}
