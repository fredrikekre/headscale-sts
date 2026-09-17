package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration for YAML strings like "5m".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dd, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(dd)
	return nil
}

// KeyParams describe the preauth key minted for a matched rule.
type KeyParams struct {
	// Ephemeral and Reusable are pointers so that "unset" can be
	// distinguished from an explicit false; defaults are ephemeral=true,
	// reusable=false.
	Ephemeral *bool    `yaml:"ephemeral"`
	Reusable  *bool    `yaml:"reusable"`
	Expiry    Duration `yaml:"expiry"`
}

func (k *KeyParams) ephemeral() bool {
	if k.Ephemeral == nil {
		return true
	}
	return *k.Ephemeral
}

func (k *KeyParams) reusable() bool {
	if k.Reusable == nil {
		return false
	}
	return *k.Reusable
}

func (k *KeyParams) expiry() time.Duration {
	if k.Expiry == 0 {
		return 5 * time.Minute
	}
	return time.Duration(k.Expiry)
}

// Rule maps claims of a verified token to preauth key parameters. All
// claims in Match must be equal to the corresponding token claim.
type Rule struct {
	Match map[string]string `yaml:"match"`
	Tags  []string          `yaml:"tags"`
	Key   KeyParams         `yaml:"key"`
}

// Trust is a trusted token issuer together with the rules for tokens it
// issues.
type Trust struct {
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	Rules    []Rule `yaml:"rules"`
}

type HeadscaleConfig struct {
	URL        string `yaml:"url"`
	APIKey     string `yaml:"api_key"`
	APIKeyFile string `yaml:"api_key_file"`
}

type Config struct {
	Listen    string          `yaml:"listen"`
	Headscale HeadscaleConfig `yaml:"headscale"`
	Trusts    []Trust         `yaml:"trusts"`
}

// LoadConfig parses the config file and resolves api_key_file into the API
// key.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, err
	}
	if cfg.Headscale.APIKeyFile != "" {
		// Environment variables are expanded so that the config can refer
		// to e.g. ${CREDENTIALS_DIRECTORY}/apikey when the key is passed
		// with systemd's LoadCredential=.
		key, err := os.ReadFile(os.ExpandEnv(cfg.Headscale.APIKeyFile))
		if err != nil {
			return nil, fmt.Errorf("reading api_key_file: %w", err)
		}
		cfg.Headscale.APIKey = strings.TrimSpace(string(key))
	}
	return cfg, nil
}

// ParseConfig parses and validates the config without touching the
// filesystem.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *Config) validate() error {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8470"
	}
	if cfg.Headscale.URL == "" {
		return errors.New("headscale.url is required")
	}
	if cfg.Headscale.APIKey == "" && cfg.Headscale.APIKeyFile == "" {
		return errors.New("one of headscale.api_key and headscale.api_key_file is required")
	}
	if cfg.Headscale.APIKey != "" && cfg.Headscale.APIKeyFile != "" {
		return errors.New("only one of headscale.api_key and headscale.api_key_file may be set")
	}
	if len(cfg.Trusts) == 0 {
		return errors.New("at least one trust is required")
	}
	for i, trust := range cfg.Trusts {
		if trust.Issuer == "" {
			return fmt.Errorf("trusts[%d]: issuer is required", i)
		}
		if trust.Audience == "" {
			return fmt.Errorf("trusts[%d]: audience is required", i)
		}
		if len(trust.Rules) == 0 {
			return fmt.Errorf("trusts[%d]: at least one rule is required", i)
		}
		for j, rule := range trust.Rules {
			// An empty match set would match any token from the issuer;
			// require an explicit claim pin.
			if len(rule.Match) == 0 {
				return fmt.Errorf("trusts[%d].rules[%d]: at least one match claim is required", i, j)
			}
			// Only tagged keys are supported (a key must be tagged or
			// user-owned, and this service has no notion of users).
			if len(rule.Tags) == 0 {
				return fmt.Errorf("trusts[%d].rules[%d]: at least one tag is required", i, j)
			}
			for _, tag := range rule.Tags {
				if !strings.HasPrefix(tag, "tag:") {
					return fmt.Errorf("trusts[%d].rules[%d]: tag %q must start with \"tag:\"", i, j, tag)
				}
			}
		}
	}
	return nil
}
