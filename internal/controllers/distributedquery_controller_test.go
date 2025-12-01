package controllers

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

func TestHandleTTL(t *testing.T) {
	r := &DistributedQueryReconciler{}

	now := metav1.Now()
	oneHourAgo := metav1.NewTime(now.Add(-1 * time.Hour))
	tenMinutesAgo := metav1.NewTime(now.Add(-10 * time.Minute))

	tests := []struct {
		name           string
		dq             *osqueryv1alpha1.DistributedQuery
		expectedDelete bool
	}{
		{
			name: "pending - no deletion",
			dq: &osqueryv1alpha1.DistributedQuery{
				Spec: osqueryv1alpha1.DistributedQuerySpec{
					TTL: "30m",
				},
				Status: osqueryv1alpha1.DistributedQueryStatus{
					Phase: PhasePending,
				},
			},
			expectedDelete: false,
		},
		{
			name: "running - no deletion",
			dq: &osqueryv1alpha1.DistributedQuery{
				Spec: osqueryv1alpha1.DistributedQuerySpec{
					TTL: "30m",
				},
				Status: osqueryv1alpha1.DistributedQueryStatus{
					Phase: PhaseRunning,
				},
			},
			expectedDelete: false,
		},
		{
			name: "completed - not expired",
			dq: &osqueryv1alpha1.DistributedQuery{
				Spec: osqueryv1alpha1.DistributedQuerySpec{
					TTL: "1h",
				},
				Status: osqueryv1alpha1.DistributedQueryStatus{
					Phase:          PhaseCompleted,
					CompletionTime: &tenMinutesAgo,
				},
			},
			expectedDelete: false,
		},
		{
			name: "completed - expired",
			dq: &osqueryv1alpha1.DistributedQuery{
				Spec: osqueryv1alpha1.DistributedQuerySpec{
					TTL: "30m",
				},
				Status: osqueryv1alpha1.DistributedQueryStatus{
					Phase:          PhaseCompleted,
					CompletionTime: &oneHourAgo,
				},
			},
			expectedDelete: true,
		},
		{
			name: "failed - expired",
			dq: &osqueryv1alpha1.DistributedQuery{
				Spec: osqueryv1alpha1.DistributedQuerySpec{
					TTL: "30m",
				},
				Status: osqueryv1alpha1.DistributedQueryStatus{
					Phase:          PhaseFailed,
					CompletionTime: &oneHourAgo,
				},
			},
			expectedDelete: true,
		},
		{
			name: "timedOut - expired",
			dq: &osqueryv1alpha1.DistributedQuery{
				Spec: osqueryv1alpha1.DistributedQuerySpec{
					TTL: "30m",
				},
				Status: osqueryv1alpha1.DistributedQueryStatus{
					Phase:          PhaseTimedOut,
					CompletionTime: &oneHourAgo,
				},
			},
			expectedDelete: true,
		},
		{
			name: "completed - no completion time",
			dq: &osqueryv1alpha1.DistributedQuery{
				Spec: osqueryv1alpha1.DistributedQuerySpec{
					TTL: "30m",
				},
				Status: osqueryv1alpha1.DistributedQueryStatus{
					Phase:          PhaseCompleted,
					CompletionTime: nil,
				},
			},
			expectedDelete: false,
		},
		{
			name: "invalid TTL - uses default",
			dq: &osqueryv1alpha1.DistributedQuery{
				Spec: osqueryv1alpha1.DistributedQuerySpec{
					TTL: "invalid",
				},
				Status: osqueryv1alpha1.DistributedQueryStatus{
					Phase:          PhaseCompleted,
					CompletionTime: &tenMinutesAgo,
				},
			},
			expectedDelete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldDelete, err := r.handleTTL(context.TODO(), tt.dq)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedDelete, shouldDelete)
		})
	}
}

func TestQueryConfigMapPayload(t *testing.T) {
	queryData := map[string]any{
		"query":        "SELECT * FROM processes;",
		"cardinality":  1000,
		"target_nodes": []string{"node-1", "node-2", "node-3"},
		"query_id":     "abc-123-def",
	}

	jsonBytes, err := json.Marshal(queryData)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "SELECT * FROM processes;", parsed["query"])
	assert.Equal(t, float64(1000), parsed["cardinality"])
	assert.Len(t, parsed["target_nodes"], 3)
}

func TestPhaseConstants(t *testing.T) {
	assert.Equal(t, "Pending", PhasePending)
	assert.Equal(t, "Running", PhaseRunning)
	assert.Equal(t, "Completed", PhaseCompleted)
	assert.Equal(t, "Failed", PhaseFailed)
	assert.Equal(t, "TimedOut", PhaseTimedOut)
}

func TestDistributedQueryStatusUpdate(t *testing.T) {
	dq := &osqueryv1alpha1.DistributedQuery{
		Status: osqueryv1alpha1.DistributedQueryStatus{
			Phase:       PhaseRunning,
			TargetNodes: 5,
			NodeResults: []osqueryv1alpha1.NodeQueryResult{
				{NodeName: "node-1", Status: PhaseCompleted, RowCount: 10},
				{NodeName: "node-2", Status: PhaseCompleted, RowCount: 5},
				{NodeName: "node-3", Status: PhasePending},
				{NodeName: "node-4", Status: PhaseFailed, Error: "timeout"},
				{NodeName: "node-5", Status: PhasePending},
			},
		},
	}

	completed := 0
	failed := 0
	totalRows := 0

	for _, nr := range dq.Status.NodeResults {
		switch nr.Status {
		case PhaseCompleted:
			completed++
			totalRows += nr.RowCount
		case PhaseFailed, PhaseTimedOut:
			failed++
		}
	}

	assert.Equal(t, 2, completed)
	assert.Equal(t, 1, failed)
	assert.Equal(t, 15, totalRows)

	isDone := completed+failed >= dq.Status.TargetNodes
	assert.False(t, isDone, "Query should not be done with pending nodes")
}

func TestDistributedQueryTimeout(t *testing.T) {
	timeout := 60 * time.Second

	tests := []struct {
		name       string
		startTime  time.Time
		isTimedOut bool
	}{
		{
			name:       "just started",
			startTime:  time.Now(),
			isTimedOut: false,
		},
		{
			name:       "30 seconds ago",
			startTime:  time.Now().Add(-30 * time.Second),
			isTimedOut: false,
		},
		{
			name:       "59 seconds ago",
			startTime:  time.Now().Add(-59 * time.Second),
			isTimedOut: false,
		},
		{
			name:       "61 seconds ago",
			startTime:  time.Now().Add(-61 * time.Second),
			isTimedOut: true,
		},
		{
			name:       "5 minutes ago",
			startTime:  time.Now().Add(-5 * time.Minute),
			isTimedOut: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isTimedOut := time.Since(tt.startTime) > timeout
			assert.Equal(t, tt.isTimedOut, isTimedOut)
		})
	}
}

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"60s", 60 * time.Second},
		{"5m", 5 * time.Minute},
		{"1h", 1 * time.Hour},
		{"120s", 120 * time.Second},
		{"invalid", 60 * time.Second},
		{"", 60 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			timeout, err := time.ParseDuration(tt.input)
			if err != nil {
				timeout = 60 * time.Second
			}
			assert.Equal(t, tt.expected, timeout)
		})
	}
}

func TestNodeResultAggregation(t *testing.T) {
	nodeResults := []osqueryv1alpha1.NodeQueryResult{
		{
			NodeName: "node-1",
			Status:   PhaseCompleted,
			RowCount: 3,
			Rows: []map[string]string{
				{"pid": "1", "name": "systemd"},
				{"pid": "100", "name": "sshd"},
				{"pid": "200", "name": "nginx"},
			},
		},
		{
			NodeName: "node-2",
			Status:   PhaseCompleted,
			RowCount: 2,
			Rows: []map[string]string{
				{"pid": "1", "name": "systemd"},
				{"pid": "150", "name": "apache"},
			},
		},
		{
			NodeName: "node-3",
			Status:   PhaseFailed,
			Error:    "connection refused",
		},
	}

	totalRows := 0
	completedNodes := 0
	failedNodes := 0

	for _, nr := range nodeResults {
		switch nr.Status {
		case PhaseCompleted:
			completedNodes++
			totalRows += nr.RowCount
		case PhaseFailed:
			failedNodes++
		}
	}

	assert.Equal(t, 5, totalRows)
	assert.Equal(t, 2, completedNodes)
	assert.Equal(t, 1, failedNodes)
}

func TestCardinalityLimit(t *testing.T) {
	dq := &osqueryv1alpha1.DistributedQuery{
		Spec: osqueryv1alpha1.DistributedQuerySpec{
			Query:       "SELECT * FROM processes;",
			Cardinality: 100,
		},
	}

	rows := make([]map[string]string, 500)
	for i := range 500 {
		rows[i] = map[string]string{"pid": string(rune(i))}
	}

	if len(rows) > dq.Spec.Cardinality {
		rows = rows[:dq.Spec.Cardinality]
	}

	assert.Len(t, rows, 100)
}

func TestDefaultValues(t *testing.T) {
	dq := &osqueryv1alpha1.DistributedQuery{
		Spec: osqueryv1alpha1.DistributedQuerySpec{
			Query: "SELECT 1;",
		},
	}

	timeout := dq.Spec.Timeout
	if timeout == "" {
		timeout = "60s"
	}
	assert.Equal(t, "60s", timeout)

	ttl := dq.Spec.TTL
	if ttl == "" {
		ttl = "1h"
	}
	assert.Equal(t, "1h", ttl)

	cardinality := dq.Spec.Cardinality
	if cardinality == 0 {
		cardinality = 1000
	}
	assert.Equal(t, 1000, cardinality)
}

func TestNodeSelectorMatching(t *testing.T) {
	nodes := []struct {
		name   string
		labels map[string]string
	}{
		{"node-1", map[string]string{"kubernetes.io/os": "linux", "role": "worker"}},
		{"node-2", map[string]string{"kubernetes.io/os": "linux", "role": "worker"}},
		{"node-3", map[string]string{"kubernetes.io/os": "linux", "role": "control-plane"}},
		{"node-4", map[string]string{"kubernetes.io/os": "windows", "role": "worker"}},
	}

	tests := []struct {
		name          string
		selector      map[string]string
		expectedLen   int
		expectedNodes []string
	}{
		{
			name:          "empty selector - all nodes",
			selector:      nil,
			expectedLen:   4,
			expectedNodes: []string{"node-1", "node-2", "node-3", "node-4"},
		},
		{
			name:          "linux only",
			selector:      map[string]string{"kubernetes.io/os": "linux"},
			expectedLen:   3,
			expectedNodes: []string{"node-1", "node-2", "node-3"},
		},
		{
			name:          "workers only",
			selector:      map[string]string{"role": "worker"},
			expectedLen:   3,
			expectedNodes: []string{"node-1", "node-2", "node-4"},
		},
		{
			name:          "linux workers",
			selector:      map[string]string{"kubernetes.io/os": "linux", "role": "worker"},
			expectedLen:   2,
			expectedNodes: []string{"node-1", "node-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matched []string
			for _, node := range nodes {
				if matchesNodeSelector(node.labels, tt.selector) {
					matched = append(matched, node.name)
				}
			}
			assert.Len(t, matched, tt.expectedLen)
			assert.ElementsMatch(t, tt.expectedNodes, matched)
		})
	}
}

func TestQueryResultLinking(t *testing.T) {
	dqName := "hunt-log4shell"

	result := &osqueryv1alpha1.QueryResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hunt-log4shell-node1-1234567890",
			Namespace: "osquery-system",
		},
		Spec: osqueryv1alpha1.QueryResultSpec{
			QueryName:           "hunt-log4shell",
			DistributedQueryRef: dqName,
			NodeName:            "node-1",
			Rows: []map[string]string{
				{"path": "/opt/app/log4j-2.14.jar", "sha256": "abc123"},
			},
		},
	}

	assert.Equal(t, dqName, result.Spec.DistributedQueryRef)
	assert.Equal(t, "node-1", result.Spec.NodeName)
	assert.Len(t, result.Spec.Rows, 1)
}
