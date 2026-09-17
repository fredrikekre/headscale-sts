package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HeadscaleClient mints preauth keys.
type HeadscaleClient interface {
	CreatePreAuthKey(ctx context.Context, tags []string, ephemeral, reusable bool, expiry time.Duration) (string, error)
}

type headscaleClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func NewHeadscaleClient(cfg HeadscaleConfig) HeadscaleClient {
	return &headscaleClient{
		baseURL: strings.TrimRight(cfg.URL, "/"),
		apiKey:  cfg.APIKey,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *headscaleClient) CreatePreAuthKey(ctx context.Context, tags []string, ephemeral, reusable bool, expiry time.Duration) (string, error) {
	// "user": "0" mirrors what the headscale CLI sends when --user is not
	// given; tagged keys are not tied to a user (headscale >= 0.29).
	reqBody, err := json.Marshal(map[string]any{
		"user":       "0",
		"reusable":   reusable,
		"ephemeral":  ephemeral,
		"aclTags":    tags,
		"expiration": time.Now().Add(expiry).UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/preauthkey", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("headscale request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("reading headscale response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("headscale returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		PreAuthKey struct {
			Key string `json:"key"`
		} `json:"preAuthKey"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("parsing headscale response: %w", err)
	}
	if parsed.PreAuthKey.Key == "" {
		return "", fmt.Errorf("headscale response contained no key")
	}
	return parsed.PreAuthKey.Key, nil
}
