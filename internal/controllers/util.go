package controllers

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

// LabelsMatch returns true if all labels in 'want' exist in 'have' with matching values.
// An empty 'want' map always matches.
func LabelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// ValidateURL parses rawURL and ensures it uses an allowed scheme (http or https).
func ValidateURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q: only http and https are allowed", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("URL has no host")
	}
	return u.String(), nil
}

// ParseDurationOrDefault parses a duration string, returning the default if parsing fails or the string is empty.
func ParseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}
