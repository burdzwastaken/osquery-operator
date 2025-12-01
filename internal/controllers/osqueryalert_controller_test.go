package controllers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

func TestEvaluateRowCount(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	tests := []struct {
		name     string
		cond     *osqueryv1alpha1.RowCountCondition
		count    int
		expected bool
	}{
		{
			name:     "nil condition",
			cond:     nil,
			count:    5,
			expected: false,
		},
		{
			name:     "gt - true",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "gt", Value: 3},
			count:    5,
			expected: true,
		},
		{
			name:     "gt - false",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "gt", Value: 5},
			count:    5,
			expected: false,
		},
		{
			name:     "gte - equal",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "gte", Value: 5},
			count:    5,
			expected: true,
		},
		{
			name:     "gte - greater",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "gte", Value: 3},
			count:    5,
			expected: true,
		},
		{
			name:     "lt - true",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "lt", Value: 10},
			count:    5,
			expected: true,
		},
		{
			name:     "lt - false",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "lt", Value: 5},
			count:    5,
			expected: false,
		},
		{
			name:     "lte - equal",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "lte", Value: 5},
			count:    5,
			expected: true,
		},
		{
			name:     "eq - true",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "eq", Value: 5},
			count:    5,
			expected: true,
		},
		{
			name:     "eq - false",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "eq", Value: 3},
			count:    5,
			expected: false,
		},
		{
			name:     "unknown operator",
			cond:     &osqueryv1alpha1.RowCountCondition{Operator: "unknown", Value: 5},
			count:    5,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.evaluateRowCount(tt.cond, tt.count)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFieldMatches(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	tests := []struct {
		name     string
		match    osqueryv1alpha1.FieldMatch
		row      map[string]string
		expected bool
	}{
		{
			name:     "field not exists",
			match:    osqueryv1alpha1.FieldMatch{Field: "name", Equals: "test"},
			row:      map[string]string{"other": "value"},
			expected: false,
		},
		{
			name:     "equals - match",
			match:    osqueryv1alpha1.FieldMatch{Field: "name", Equals: "xmrig"},
			row:      map[string]string{"name": "xmrig"},
			expected: true,
		},
		{
			name:     "equals - no match",
			match:    osqueryv1alpha1.FieldMatch{Field: "name", Equals: "xmrig"},
			row:      map[string]string{"name": "bash"},
			expected: false,
		},
		{
			name:     "notEquals - match",
			match:    osqueryv1alpha1.FieldMatch{Field: "name", NotEquals: "bash"},
			row:      map[string]string{"name": "xmrig"},
			expected: true,
		},
		{
			name:     "notEquals - no match",
			match:    osqueryv1alpha1.FieldMatch{Field: "name", NotEquals: "xmrig"},
			row:      map[string]string{"name": "xmrig"},
			expected: false,
		},
		{
			name:     "contains - match",
			match:    osqueryv1alpha1.FieldMatch{Field: "path", Contains: "/tmp/"},
			row:      map[string]string{"path": "/tmp/malware"},
			expected: true,
		},
		{
			name:     "contains - no match",
			match:    osqueryv1alpha1.FieldMatch{Field: "path", Contains: "/tmp/"},
			row:      map[string]string{"path": "/usr/bin/bash"},
			expected: false,
		},
		{
			name:     "regex - match simple",
			match:    osqueryv1alpha1.FieldMatch{Field: "name", Regex: "xmrig|minerd"},
			row:      map[string]string{"name": "xmrig"},
			expected: true,
		},
		{
			name:     "regex - match complex",
			match:    osqueryv1alpha1.FieldMatch{Field: "cmdline", Regex: "stratum\\+tcp://"},
			row:      map[string]string{"cmdline": "./miner stratum+tcp://pool.example.com:3333"},
			expected: true,
		},
		{
			name:     "regex - no match",
			match:    osqueryv1alpha1.FieldMatch{Field: "name", Regex: "xmrig|minerd"},
			row:      map[string]string{"name": "bash"},
			expected: false,
		},
		{
			name:     "regex - invalid regex",
			match:    osqueryv1alpha1.FieldMatch{Field: "name", Regex: "[invalid"},
			row:      map[string]string{"name": "anything"},
			expected: false,
		},
		{
			name:     "no conditions - match",
			match:    osqueryv1alpha1.FieldMatch{Field: "name"},
			row:      map[string]string{"name": "anything"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.fieldMatches(tt.match, tt.row)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateRowMatch(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	tests := []struct {
		name     string
		matches  []osqueryv1alpha1.FieldMatch
		rows     []map[string]string
		expected bool
	}{
		{
			name:     "empty matches",
			matches:  []osqueryv1alpha1.FieldMatch{},
			rows:     []map[string]string{{"name": "test"}},
			expected: false,
		},
		{
			name:     "empty rows",
			matches:  []osqueryv1alpha1.FieldMatch{{Field: "name", Equals: "test"}},
			rows:     []map[string]string{},
			expected: false,
		},
		{
			name: "single condition - match",
			matches: []osqueryv1alpha1.FieldMatch{
				{Field: "name", Regex: "xmrig|minerd"},
			},
			rows: []map[string]string{
				{"name": "bash", "path": "/usr/bin/bash"},
				{"name": "xmrig", "path": "/tmp/xmrig"},
			},
			expected: true,
		},
		{
			name: "single condition - no match",
			matches: []osqueryv1alpha1.FieldMatch{
				{Field: "name", Regex: "xmrig|minerd"},
			},
			rows: []map[string]string{
				{"name": "bash", "path": "/usr/bin/bash"},
				{"name": "systemd", "path": "/usr/lib/systemd"},
			},
			expected: false,
		},
		{
			name: "multiple conditions - all match same row",
			matches: []osqueryv1alpha1.FieldMatch{
				{Field: "name", Regex: "xmrig|minerd"},
				{Field: "path", Contains: "/tmp/"},
			},
			rows: []map[string]string{
				{"name": "bash", "path": "/usr/bin/bash"},
				{"name": "xmrig", "path": "/tmp/xmrig"},
			},
			expected: true,
		},
		{
			name: "multiple conditions - different rows",
			matches: []osqueryv1alpha1.FieldMatch{
				{Field: "name", Regex: "xmrig"},
				{Field: "path", Contains: "/tmp/"},
			},
			rows: []map[string]string{
				{"name": "xmrig", "path": "/usr/bin/xmrig"},
				{"name": "bash", "path": "/tmp/script.sh"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.evaluateRowMatch(tt.matches, tt.rows)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateFieldThreshold(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	tests := []struct {
		name     string
		cond     *osqueryv1alpha1.FieldThresholdCondition
		rows     []map[string]string
		expected bool
	}{
		{
			name:     "nil condition",
			cond:     nil,
			rows:     []map[string]string{{"port": "8080"}},
			expected: false,
		},
		{
			name:     "field not exists",
			cond:     &osqueryv1alpha1.FieldThresholdCondition{Field: "port", Operator: "gt", Value: 1000},
			rows:     []map[string]string{{"name": "test"}},
			expected: false,
		},
		{
			name:     "non-numeric field",
			cond:     &osqueryv1alpha1.FieldThresholdCondition{Field: "name", Operator: "gt", Value: 100},
			rows:     []map[string]string{{"name": "bash"}},
			expected: false,
		},
		{
			name:     "gt - match",
			cond:     &osqueryv1alpha1.FieldThresholdCondition{Field: "port", Operator: "gt", Value: 1000},
			rows:     []map[string]string{{"port": "8080"}},
			expected: true,
		},
		{
			name:     "gt - no match",
			cond:     &osqueryv1alpha1.FieldThresholdCondition{Field: "port", Operator: "gt", Value: 9000},
			rows:     []map[string]string{{"port": "8080"}},
			expected: false,
		},
		{
			name: "multiple rows - one matches",
			cond: &osqueryv1alpha1.FieldThresholdCondition{Field: "connections", Operator: "gte", Value: 1000},
			rows: []map[string]string{
				{"connections": "50"},
				{"connections": "1500"},
				{"connections": "200"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.evaluateFieldThreshold(tt.cond, tt.rows)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateCondition(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	tests := []struct {
		name     string
		alert    *osqueryv1alpha1.OsqueryAlert
		result   *osqueryv1alpha1.QueryResult
		expected bool
	}{
		{
			name: "type any - with rows",
			alert: &osqueryv1alpha1.OsqueryAlert{
				Spec: osqueryv1alpha1.OsqueryAlertSpec{
					Condition: osqueryv1alpha1.AlertCondition{Type: "any"},
				},
			},
			result: &osqueryv1alpha1.QueryResult{
				Spec: osqueryv1alpha1.QueryResultSpec{
					Rows: []map[string]string{{"name": "test"}},
				},
			},
			expected: true,
		},
		{
			name: "type any - no rows",
			alert: &osqueryv1alpha1.OsqueryAlert{
				Spec: osqueryv1alpha1.OsqueryAlertSpec{
					Condition: osqueryv1alpha1.AlertCondition{Type: "any"},
				},
			},
			result: &osqueryv1alpha1.QueryResult{
				Spec: osqueryv1alpha1.QueryResultSpec{
					Rows: []map[string]string{},
				},
			},
			expected: false,
		},
		{
			name: "unknown type",
			alert: &osqueryv1alpha1.OsqueryAlert{
				Spec: osqueryv1alpha1.OsqueryAlertSpec{
					Condition: osqueryv1alpha1.AlertCondition{Type: "unknown"},
				},
			},
			result: &osqueryv1alpha1.QueryResult{
				Spec: osqueryv1alpha1.QueryResultSpec{
					Rows: []map[string]string{{"name": "test"}},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.evaluateCondition(tt.alert, tt.result)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestThrottling(t *testing.T) {
	r := &OsqueryAlertReconciler{
		throttleCache: make(map[string][]time.Time),
	}

	alert := &osqueryv1alpha1.OsqueryAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-alert",
			Namespace: "default",
		},
		Spec: osqueryv1alpha1.OsqueryAlertSpec{
			Throttle: &osqueryv1alpha1.AlertThrottle{
				Period:    "1m",
				MaxAlerts: 2,
			},
		},
	}

	result := &osqueryv1alpha1.QueryResult{
		Spec: osqueryv1alpha1.QueryResultSpec{
			NodeName: "node-1",
		},
	}

	assert.False(t, r.isThrottled(alert, result), "First alert should not be throttled")
	r.recordThrottle(alert, result)

	assert.False(t, r.isThrottled(alert, result), "Second alert should not be throttled")
	r.recordThrottle(alert, result)

	assert.True(t, r.isThrottled(alert, result), "Third alert should be throttled")
}

func TestThrottlingWithGroupBy(t *testing.T) {
	r := &OsqueryAlertReconciler{
		throttleCache: make(map[string][]time.Time),
	}

	alert := &osqueryv1alpha1.OsqueryAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-alert",
			Namespace: "default",
		},
		Spec: osqueryv1alpha1.OsqueryAlertSpec{
			Throttle: &osqueryv1alpha1.AlertThrottle{
				Period:    "1m",
				MaxAlerts: 1,
				GroupBy:   []string{"nodeName"},
			},
		},
	}

	result1 := &osqueryv1alpha1.QueryResult{
		Spec: osqueryv1alpha1.QueryResultSpec{
			NodeName: "node-1",
		},
	}

	result2 := &osqueryv1alpha1.QueryResult{
		Spec: osqueryv1alpha1.QueryResultSpec{
			NodeName: "node-2",
		},
	}

	assert.False(t, r.isThrottled(alert, result1))
	r.recordThrottle(alert, result1)

	assert.False(t, r.isThrottled(alert, result2))
	r.recordThrottle(alert, result2)

	assert.True(t, r.isThrottled(alert, result1))

	assert.True(t, r.isThrottled(alert, result2))
}

func TestNoThrottle(t *testing.T) {
	r := &OsqueryAlertReconciler{
		throttleCache: make(map[string][]time.Time),
	}

	alert := &osqueryv1alpha1.OsqueryAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-alert",
			Namespace: "default",
		},
		Spec: osqueryv1alpha1.OsqueryAlertSpec{
			// No throttle config
		},
	}

	result := &osqueryv1alpha1.QueryResult{
		Spec: osqueryv1alpha1.QueryResultSpec{
			NodeName: "node-1",
		},
	}

	for range 10 {
		assert.False(t, r.isThrottled(alert, result), "Alert should not be throttled without config")
	}
}

func TestBuildThrottleKey(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	tests := []struct {
		name     string
		alert    *osqueryv1alpha1.OsqueryAlert
		result   *osqueryv1alpha1.QueryResult
		expected string
	}{
		{
			name: "no groupBy",
			alert: &osqueryv1alpha1.OsqueryAlert{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-alert",
					Namespace: "default",
				},
			},
			result:   &osqueryv1alpha1.QueryResult{},
			expected: "default/test-alert",
		},
		{
			name: "groupBy with decorations",
			alert: &osqueryv1alpha1.OsqueryAlert{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-alert",
					Namespace: "default",
				},
				Spec: osqueryv1alpha1.OsqueryAlertSpec{
					Throttle: &osqueryv1alpha1.AlertThrottle{
						GroupBy: []string{"hostname"},
					},
				},
			},
			result: &osqueryv1alpha1.QueryResult{
				Spec: osqueryv1alpha1.QueryResultSpec{
					Decorations: map[string]string{"hostname": "node-1"},
				},
			},
			expected: "default/test-alert:node-1",
		},
		{
			name: "groupBy with row data",
			alert: &osqueryv1alpha1.OsqueryAlert{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-alert",
					Namespace: "default",
				},
				Spec: osqueryv1alpha1.OsqueryAlertSpec{
					Throttle: &osqueryv1alpha1.AlertThrottle{
						GroupBy: []string{"name", "pid"},
					},
				},
			},
			result: &osqueryv1alpha1.QueryResult{
				Spec: osqueryv1alpha1.QueryResultSpec{
					Rows: []map[string]string{
						{"name": "xmrig", "pid": "1234"},
					},
				},
			},
			expected: "default/test-alert:xmrig,1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.buildThrottleKey(tt.alert, tt.result)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSeverityToColor(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "#dc3545"},
		{"high", "#fd7e14"},
		{"medium", "#ffc107"},
		{"low", "#17a2b8"},
		{"info", "#6c757d"},
		{"unknown", "#6c757d"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			assert.Equal(t, tt.expected, r.severityToColor(tt.severity))
		})
	}
}

func TestLabelsMatch(t *testing.T) {
	tests := []struct {
		name     string
		have     map[string]string
		want     map[string]string
		expected bool
	}{
		{
			name:     "empty want",
			have:     map[string]string{"a": "1"},
			want:     map[string]string{},
			expected: true,
		},
		{
			name:     "exact match",
			have:     map[string]string{"a": "1", "b": "2"},
			want:     map[string]string{"a": "1", "b": "2"},
			expected: true,
		},
		{
			name:     "subset match",
			have:     map[string]string{"a": "1", "b": "2", "c": "3"},
			want:     map[string]string{"a": "1"},
			expected: true,
		},
		{
			name:     "missing key",
			have:     map[string]string{"a": "1"},
			want:     map[string]string{"a": "1", "b": "2"},
			expected: false,
		},
		{
			name:     "wrong value",
			have:     map[string]string{"a": "1"},
			want:     map[string]string{"a": "2"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := labelsMatch(tt.have, tt.want)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCryptominerDetection(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	alert := &osqueryv1alpha1.OsqueryAlert{
		Spec: osqueryv1alpha1.OsqueryAlertSpec{
			Condition: osqueryv1alpha1.AlertCondition{
				Type: "rowMatch",
				RowMatch: []osqueryv1alpha1.FieldMatch{
					{Field: "name", Regex: "(xmrig|minerd|cryptonight|stratum)"},
				},
			},
		},
	}

	tests := []struct {
		name     string
		rows     []map[string]string
		expected bool
	}{
		{
			name: "xmrig detected",
			rows: []map[string]string{
				{"pid": "1234", "name": "xmrig", "path": "/tmp/xmrig", "cmdline": "./xmrig -o pool.example.com"},
			},
			expected: true,
		},
		{
			name: "minerd detected",
			rows: []map[string]string{
				{"pid": "5678", "name": "minerd", "path": "/dev/shm/minerd"},
			},
			expected: true,
		},
		{
			name: "normal processes",
			rows: []map[string]string{
				{"pid": "1", "name": "systemd", "path": "/usr/lib/systemd/systemd"},
				{"pid": "100", "name": "bash", "path": "/usr/bin/bash"},
				{"pid": "200", "name": "nginx", "path": "/usr/sbin/nginx"},
			},
			expected: false,
		},
		{
			name:     "empty results",
			rows:     []map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &osqueryv1alpha1.QueryResult{
				Spec: osqueryv1alpha1.QueryResultSpec{
					Rows: tt.rows,
				},
			}
			assert.Equal(t, tt.expected, r.evaluateCondition(alert, result))
		})
	}
}

func TestPrivilegedContainerAlert(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	alert := &osqueryv1alpha1.OsqueryAlert{
		Spec: osqueryv1alpha1.OsqueryAlertSpec{
			Condition: osqueryv1alpha1.AlertCondition{
				Type: "rowCount",
				RowCount: &osqueryv1alpha1.RowCountCondition{
					Operator: "gt",
					Value:    0,
				},
			},
		},
	}

	resultWithPrivileged := &osqueryv1alpha1.QueryResult{
		Spec: osqueryv1alpha1.QueryResultSpec{
			Rows: []map[string]string{
				{"id": "abc123", "name": "evil-container", "privileged": "1"},
			},
		},
	}
	assert.True(t, r.evaluateCondition(alert, resultWithPrivileged))

	resultEmpty := &osqueryv1alpha1.QueryResult{
		Spec: osqueryv1alpha1.QueryResultSpec{
			Rows: []map[string]string{},
		},
	}
	assert.False(t, r.evaluateCondition(alert, resultEmpty))
}

func TestConnectionThresholdAlert(t *testing.T) {
	r := &OsqueryAlertReconciler{}

	alert := &osqueryv1alpha1.OsqueryAlert{
		Spec: osqueryv1alpha1.OsqueryAlertSpec{
			Condition: osqueryv1alpha1.AlertCondition{
				Type: "fieldThreshold",
				FieldThreshold: &osqueryv1alpha1.FieldThresholdCondition{
					Field:    "connection_count",
					Operator: "gte",
					Value:    100,
				},
			},
		},
	}

	tests := []struct {
		name     string
		rows     []map[string]string
		expected bool
	}{
		{
			name: "high connection count",
			rows: []map[string]string{
				{"pid": "1234", "name": "suspicious", "connection_count": "500"},
			},
			expected: true,
		},
		{
			name: "normal connection count",
			rows: []map[string]string{
				{"pid": "1234", "name": "nginx", "connection_count": "50"},
			},
			expected: false,
		},
		{
			name: "exactly at threshold",
			rows: []map[string]string{
				{"pid": "1234", "name": "app", "connection_count": "100"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &osqueryv1alpha1.QueryResult{
				Spec: osqueryv1alpha1.QueryResultSpec{
					Rows: tt.rows,
				},
			}
			assert.Equal(t, tt.expected, r.evaluateCondition(alert, result))
		})
	}
}
