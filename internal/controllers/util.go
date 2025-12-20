package controllers

import "time"

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
