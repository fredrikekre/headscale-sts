package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConfig = `
listen: "127.0.0.1:9999"
headscale:
  url: http://127.0.0.1:8080
  api_key: secret
trusts:
  - issuer: https://token.actions.githubusercontent.com
    audience: https://headscale.example.org/sts
    rules:
      - match:
          repository: Org/Repo
          ref: refs/heads/master
        tags: [tag:logsync]
        key:
          ephemeral: true
          reusable: false
          expiry: 5m
`

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9999" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.Headscale.APIKey != "secret" {
		t.Errorf("APIKey = %q", cfg.Headscale.APIKey)
	}
	rule := cfg.Trusts[0].Rules[0]
	if rule.Match["repository"] != "Org/Repo" {
		t.Errorf("Match = %v", rule.Match)
	}
	if !rule.Key.ephemeral() || rule.Key.reusable() || rule.Key.expiry() != 5*time.Minute {
		t.Errorf("KeyParams = %+v", rule.Key)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
headscale:
  url: http://127.0.0.1:8080
  api_key: secret
trusts:
  - issuer: https://issuer.example.org
    audience: aud
    rules:
      - match: {repository: Org/Repo}
        tags: [tag:ci]
`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8470" {
		t.Errorf("default Listen = %q", cfg.Listen)
	}
	rule := cfg.Trusts[0].Rules[0]
	if !rule.Key.ephemeral() {
		t.Error("default ephemeral should be true")
	}
	if rule.Key.reusable() {
		t.Error("default reusable should be false")
	}
	if rule.Key.expiry() != 5*time.Minute {
		t.Errorf("default expiry = %v", rule.Key.expiry())
	}
}

func TestLoadConfigAPIKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyfile := filepath.Join(dir, "apikey")
	if err := os.WriteFile(keyfile, []byte("filekey\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configfile := filepath.Join(dir, "config.yaml")
	config := `
headscale:
  url: http://127.0.0.1:8080
  api_key_file: ` + keyfile + `
trusts:
  - issuer: https://issuer.example.org
    audience: aud
    rules:
      - match: {repository: Org/Repo}
        tags: [tag:ci]
`
	if err := os.WriteFile(configfile, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configfile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Headscale.APIKey != "filekey" {
		t.Errorf("APIKey from file = %q", cfg.Headscale.APIKey)
	}
}

// api_key_file supports env expansion, e.g. systemd's $CREDENTIALS_DIRECTORY.
func TestLoadConfigAPIKeyFileEnvExpansion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "apikey"), []byte("envkey"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	configfile := filepath.Join(dir, "config.yaml")
	config := `
headscale:
  url: http://127.0.0.1:8080
  api_key_file: ${CREDENTIALS_DIRECTORY}/apikey
trusts:
  - issuer: https://issuer.example.org
    audience: aud
    rules:
      - match: {repository: Org/Repo}
        tags: [tag:ci]
`
	if err := os.WriteFile(configfile, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configfile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Headscale.APIKey != "envkey" {
		t.Errorf("APIKey = %q", cfg.Headscale.APIKey)
	}
}

// The example config in the repository must always be valid.
func TestExampleConfig(t *testing.T) {
	data, err := os.ReadFile("config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("ParseConfig(config.example.yaml): %v", err)
	}
	if len(cfg.Trusts) == 0 || len(cfg.Trusts[0].Rules) == 0 {
		t.Error("example config should have a trust with rules")
	}
}

func TestParseConfigErrors(t *testing.T) {
	cases := map[string]struct {
		config  string
		wantErr string
	}{
		"missing headscale url": {
			config: `
headscale: {api_key: secret}
trusts:
  - issuer: i
    audience: a
    rules: [{match: {r: v}, tags: [tag:ci]}]
`,
			wantErr: "headscale.url",
		},
		"missing api key": {
			config: `
headscale: {url: http://x}
trusts:
  - issuer: i
    audience: a
    rules: [{match: {r: v}, tags: [tag:ci]}]
`,
			wantErr: "api_key",
		},
		"both api key and file": {
			config: `
headscale: {url: http://x, api_key: a, api_key_file: /nonexistent}
trusts:
  - issuer: i
    audience: a
    rules: [{match: {r: v}, tags: [tag:ci]}]
`,
			wantErr: "only one of",
		},
		"no trusts": {
			config:  `headscale: {url: http://x, api_key: secret}`,
			wantErr: "at least one trust",
		},
		"missing audience": {
			config: `
headscale: {url: http://x, api_key: secret}
trusts:
  - issuer: i
    rules: [{match: {r: v}, tags: [tag:ci]}]
`,
			wantErr: "audience",
		},
		"empty match": {
			config: `
headscale: {url: http://x, api_key: secret}
trusts:
  - issuer: i
    audience: a
    rules: [{tags: [tag:ci]}]
`,
			wantErr: "match",
		},
		"no tags": {
			config: `
headscale: {url: http://x, api_key: secret}
trusts:
  - issuer: i
    audience: a
    rules: [{match: {r: v}}]
`,
			wantErr: "tag",
		},
		"bad tag prefix": {
			config: `
headscale: {url: http://x, api_key: secret}
trusts:
  - issuer: i
    audience: a
    rules: [{match: {r: v}, tags: [logsync]}]
`,
			wantErr: `must start with "tag:"`,
		},
		"unknown field": {
			config: `
headscale: {url: http://x, api_key: secret}
trusts:
  - issuer: i
    audience: a
    rules: [{match: {r: v}, tags: [tag:ci]}]
bogus: field
`,
			wantErr: "bogus",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tc.config))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}
