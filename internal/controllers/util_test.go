package controllers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLabelsMatchUtil(t *testing.T) {
	tests := []struct {
		name     string
		have     map[string]string
		want     map[string]string
		expected bool
	}{
		{
			name:     "nil want matches everything",
			have:     map[string]string{"foo": "bar"},
			want:     nil,
			expected: true,
		},
		{
			name:     "empty want matches everything",
			have:     map[string]string{"foo": "bar"},
			want:     map[string]string{},
			expected: true,
		},
		{
			name:     "exact match",
			have:     map[string]string{"foo": "bar"},
			want:     map[string]string{"foo": "bar"},
			expected: true,
		},
		{
			name:     "subset match",
			have:     map[string]string{"foo": "bar", "baz": "qux"},
			want:     map[string]string{"foo": "bar"},
			expected: true,
		},
		{
			name:     "multiple labels match",
			have:     map[string]string{"a": "1", "b": "2", "c": "3"},
			want:     map[string]string{"a": "1", "b": "2"},
			expected: true,
		},
		{
			name:     "missing key",
			have:     map[string]string{"foo": "bar"},
			want:     map[string]string{"missing": "key"},
			expected: false,
		},
		{
			name:     "wrong value",
			have:     map[string]string{"foo": "bar"},
			want:     map[string]string{"foo": "wrong"},
			expected: false,
		},
		{
			name:     "nil have with want",
			have:     nil,
			want:     map[string]string{"foo": "bar"},
			expected: false,
		},
		{
			name:     "both nil",
			have:     nil,
			want:     nil,
			expected: true,
		},
		{
			name:     "empty have with want",
			have:     map[string]string{},
			want:     map[string]string{"foo": "bar"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LabelsMatch(tt.have, tt.want)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseDurationOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		def      time.Duration
		expected time.Duration
	}{
		{
			name:     "valid duration",
			input:    "5m",
			def:      time.Hour,
			expected: 5 * time.Minute,
		},
		{
			name:     "valid duration seconds",
			input:    "30s",
			def:      time.Minute,
			expected: 30 * time.Second,
		},
		{
			name:     "valid duration hours",
			input:    "2h",
			def:      time.Minute,
			expected: 2 * time.Hour,
		},
		{
			name:     "valid complex duration",
			input:    "1h30m",
			def:      time.Minute,
			expected: 90 * time.Minute,
		},
		{
			name:     "empty string returns default",
			input:    "",
			def:      time.Hour,
			expected: time.Hour,
		},
		{
			name:     "invalid duration returns default",
			input:    "invalid",
			def:      15 * time.Minute,
			expected: 15 * time.Minute,
		},
		{
			name:     "missing unit returns default",
			input:    "100",
			def:      time.Second,
			expected: time.Second,
		},
		{
			name:     "negative duration is valid",
			input:    "-5m",
			def:      time.Hour,
			expected: -5 * time.Minute,
		},
		{
			name:     "zero duration",
			input:    "0s",
			def:      time.Hour,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseDurationOrDefault(tt.input, tt.def)
			assert.Equal(t, tt.expected, result)
		})
	}
}
