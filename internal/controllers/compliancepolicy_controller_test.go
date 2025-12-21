package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

func TestSanitizeQueryName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple id and title",
			input:    "5.1.1-Ensure core dumps are disabled",
			expected: "5_1_1_ensure_core_dumps_are_disabled",
		},
		{
			name:     "special characters removed",
			input:    "1.2.3-Test (with) special! chars@",
			expected: "1_2_3_test_with_special_chars",
		},
		{
			name:     "double underscores collapsed",
			input:    "test--double--dash",
			expected: "test_double_dash",
		},
		{
			name:     "leading/trailing underscores removed",
			input:    "-leading-trailing-",
			expected: "leading_trailing",
		},
		{
			name:     "truncation at 64 chars",
			input:    "this-is-a-very-long-control-name-that-exceeds-the-maximum-allowed-length-for-osquery-query-names",
			expected: "this_is_a_very_long_control_name_that_exceeds_the_maximum_allowe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeQueryName(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.LessOrEqual(t, len(result), 64)
		})
	}
}

func TestSanitizeLabelValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "underscores to hyphens",
			input:    "compliance_cis_linux",
			expected: "compliance-cis-linux",
		},
		{
			name:     "uppercase to lowercase",
			input:    "CompliancePolicy",
			expected: "compliancepolicy",
		},
		{
			name:     "special chars removed",
			input:    "test.pack@name!",
			expected: "testpackname",
		},
		{
			name:     "truncation at 63 chars",
			input:    "this-is-a-very-long-label-value-that-exceeds-the-kubernetes-limit-of-63-characters",
			expected: "this-is-a-very-long-label-value-that-exceeds-the-kubernetes-lim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeLabelValue(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.LessOrEqual(t, len(result), 63)
		})
	}
}

func TestEvaluateExpectation(t *testing.T) {
	r := &CompliancePolicyReconciler{}

	tests := []struct {
		name        string
		expectation *osqueryv1alpha1.ControlExpectation
		rowCount    int
		expected    bool
	}{
		{
			name:        "nil expectation - zero rows passes",
			expectation: nil,
			rowCount:    0,
			expected:    true,
		},
		{
			name:        "nil expectation - non-zero rows fails",
			expectation: nil,
			rowCount:    5,
			expected:    false,
		},
		{
			name: "equals - exact match passes",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "equals",
				Value:    0,
			},
			rowCount: 0,
			expected: true,
		},
		{
			name: "equals - mismatch fails",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "equals",
				Value:    0,
			},
			rowCount: 3,
			expected: false,
		},
		{
			name: "lessThan - passes when under",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "lessThan",
				Value:    5,
			},
			rowCount: 3,
			expected: true,
		},
		{
			name: "lessThan - fails when equal",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "lessThan",
				Value:    5,
			},
			rowCount: 5,
			expected: false,
		},
		{
			name: "greaterThan - passes when over",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "greaterThan",
				Value:    0,
			},
			rowCount: 1,
			expected: true,
		},
		{
			name: "greaterThan - fails when equal",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "greaterThan",
				Value:    5,
			},
			rowCount: 5,
			expected: false,
		},
		{
			name: "lessThanOrEqual - passes when equal",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "lessThanOrEqual",
				Value:    5,
			},
			rowCount: 5,
			expected: true,
		},
		{
			name: "greaterThanOrEqual - passes when equal",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "greaterThanOrEqual",
				Value:    5,
			},
			rowCount: 5,
			expected: true,
		},
		{
			name: "default operator is equals",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:  "rowCount",
				Value: 0,
			},
			rowCount: 0,
			expected: true,
		},
		{
			name: "unknown operator defaults to zero check",
			expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "unknown",
				Value:    5,
			},
			rowCount: 0,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.evaluateExpectation(tt.expectation, tt.rowCount)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateControl(t *testing.T) {
	r := &CompliancePolicyReconciler{}

	t.Run("no results returns unknown status", func(t *testing.T) {
		control := osqueryv1alpha1.ComplianceControl{
			ID:    "1.1.1",
			Title: "Test Control",
		}

		result := r.evaluateControl(control, nil)

		assert.Equal(t, "1.1.1", result.ID)
		assert.Equal(t, "unknown", result.Status)
		assert.Equal(t, "No query results available", result.Message)
		assert.Nil(t, result.RowCount)
	})

	t.Run("passing control with zero rows", func(t *testing.T) {
		control := osqueryv1alpha1.ComplianceControl{
			ID:    "1.1.1",
			Title: "Test Control",
			Expectation: &osqueryv1alpha1.ControlExpectation{
				Type:     "rowCount",
				Operator: "equals",
				Value:    0,
			},
		}

		results := []osqueryv1alpha1.QueryResult{
			{
				Spec: osqueryv1alpha1.QueryResultSpec{
					QueryName: "1_1_1_test_control",
					NodeName:  "node-1",
					Timestamp: metav1.Now(),
					Rows:      []map[string]string{},
				},
			},
		}

		result := r.evaluateControl(control, results)

		assert.Equal(t, "1.1.1", result.ID)
		assert.Equal(t, "passing", result.Status)
		require.NotNil(t, result.RowCount)
		assert.Equal(t, 0, *result.RowCount)
		assert.Empty(t, result.AffectedNodes)
	})

	t.Run("failing control with rows", func(t *testing.T) {
		control := osqueryv1alpha1.ComplianceControl{
			ID:    "1.1.1",
			Title: "Test Control",
		}

		results := []osqueryv1alpha1.QueryResult{
			{
				Spec: osqueryv1alpha1.QueryResultSpec{
					QueryName: "1_1_1_test_control",
					NodeName:  "node-1",
					Timestamp: metav1.Now(),
					Rows: []map[string]string{
						{"path": "/bad/file"},
					},
				},
			},
			{
				Spec: osqueryv1alpha1.QueryResultSpec{
					QueryName: "1_1_1_test_control",
					NodeName:  "node-2",
					Timestamp: metav1.Now(),
					Rows: []map[string]string{
						{"path": "/another/bad/file"},
						{"path": "/yet/another"},
					},
				},
			},
		}

		result := r.evaluateControl(control, results)

		assert.Equal(t, "1.1.1", result.ID)
		assert.Equal(t, "failing", result.Status)
		require.NotNil(t, result.RowCount)
		assert.Equal(t, 3, *result.RowCount)
		assert.ElementsMatch(t, []string{"node-1", "node-2"}, result.AffectedNodes)
	})
}

func TestEvaluateControls(t *testing.T) {
	r := &CompliancePolicyReconciler{}

	policy := &osqueryv1alpha1.CompliancePolicy{
		Spec: osqueryv1alpha1.CompliancePolicySpec{
			Controls: []osqueryv1alpha1.ComplianceControl{
				{
					ID:    "1.1.1",
					Title: "First Control",
				},
				{
					ID:       "1.1.2",
					Title:    "Disabled Control",
					Disabled: true,
				},
				{
					ID:    "1.1.3",
					Title: "Third Control",
				},
			},
		},
	}

	results := &osqueryv1alpha1.QueryResultList{
		Items: []osqueryv1alpha1.QueryResult{
			{
				Spec: osqueryv1alpha1.QueryResultSpec{
					QueryName: "1_1_1_first_control",
					NodeName:  "node-1",
					Timestamp: metav1.Now(),
					Rows:      []map[string]string{},
				},
			},
		},
	}

	controlResults := r.evaluateControls(policy, results)

	assert.Len(t, controlResults, 2)
	assert.Equal(t, "1.1.1", controlResults[0].ID)
	assert.Equal(t, "passing", controlResults[0].Status)
	assert.Equal(t, "1.1.3", controlResults[1].ID)
	assert.Equal(t, "unknown", controlResults[1].Status)
}

func TestBuildOsqueryPack(t *testing.T) {
	r := &CompliancePolicyReconciler{}

	policy := &osqueryv1alpha1.CompliancePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cis-linux",
		},
		Spec: osqueryv1alpha1.CompliancePolicySpec{
			Framework: "cis",
			Version:   "1.8.0",
			Platform:  "linux",
			Controls: []osqueryv1alpha1.ComplianceControl{
				{
					ID:          "1.1.1",
					Title:       "Test Control",
					Query:       "SELECT * FROM test;",
					Interval:    300,
					Severity:    "high",
					Description: "Test description",
					Remediation: "Fix it",
				},
				{
					ID:       "1.1.2",
					Title:    "Disabled",
					Query:    "SELECT 1;",
					Disabled: true,
				},
				{
					ID:    "1.1.3",
					Title: "Defaults",
					Query: "SELECT 2;",
				},
			},
		},
	}

	pack := r.buildOsqueryPack(policy)

	assert.Equal(t, "compliance-cis-linux", pack.Name)
	assert.Equal(t, "osquery-system", pack.Namespace)
	assert.Equal(t, "cis-linux", pack.Labels[LabelCompliancePolicy])
	assert.Equal(t, "true", pack.Labels[LabelComplianceManaged])
	assert.Equal(t, "true", pack.Labels["osquery.burdz.net/enabled"])
	assert.Equal(t, "linux", pack.Spec.Platform)
	assert.Len(t, pack.Spec.Queries, 2)

	q1 := pack.Spec.Queries[0]
	assert.Equal(t, "1_1_1_test_control", q1.Name)
	assert.Equal(t, "SELECT * FROM test;", q1.Query)
	assert.Equal(t, 300, q1.Interval)
	assert.Equal(t, "high", q1.Severity)
	assert.True(t, q1.Snapshot)
	assert.Contains(t, q1.Description, "Test description")
	assert.Contains(t, q1.Description, "Remediation: Fix it")

	q2 := pack.Spec.Queries[1]
	assert.Equal(t, "1_1_3_defaults", q2.Name)
	assert.Equal(t, 3600, q2.Interval)
	assert.Equal(t, "medium", q2.Severity)
}

func TestFindCompliancePolicyForQueryResult(t *testing.T) {
	r := &CompliancePolicyReconciler{}

	tests := []struct {
		name           string
		qr             *osqueryv1alpha1.QueryResult
		expectedPolicy string
	}{
		{
			name: "compliance pack query result",
			qr: &osqueryv1alpha1.QueryResult{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						LabelPack: "compliance-cis-linux",
					},
				},
			},
			expectedPolicy: "cis-linux",
		},
		{
			name: "non-compliance pack",
			qr: &osqueryv1alpha1.QueryResult{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						LabelPack: "security-baseline",
					},
				},
			},
			expectedPolicy: "",
		},
		{
			name: "no pack label",
			qr: &osqueryv1alpha1.QueryResult{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{},
				},
			},
			expectedPolicy: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := r.findCompliancePolicyForQueryResult(context.TODO(), tt.qr)
			if tt.expectedPolicy == "" {
				assert.Empty(t, requests)
			} else {
				require.Len(t, requests, 1)
				assert.Equal(t, tt.expectedPolicy, requests[0].Name)
			}
		})
	}
}

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name            string
		controlResults  []osqueryv1alpha1.ControlResult
		activeControls  int
		expectedScore   int
		expectedPassing int
		expectedFailing int
		expectedUnknown int
	}{
		{
			name: "all passing",
			controlResults: []osqueryv1alpha1.ControlResult{
				{Status: "passing"},
				{Status: "passing"},
				{Status: "passing"},
			},
			activeControls:  3,
			expectedScore:   100,
			expectedPassing: 3,
			expectedFailing: 0,
			expectedUnknown: 0,
		},
		{
			name: "all failing",
			controlResults: []osqueryv1alpha1.ControlResult{
				{Status: "failing"},
				{Status: "failing"},
			},
			activeControls:  2,
			expectedScore:   0,
			expectedPassing: 0,
			expectedFailing: 2,
			expectedUnknown: 0,
		},
		{
			name: "mixed results",
			controlResults: []osqueryv1alpha1.ControlResult{
				{Status: "passing"},
				{Status: "failing"},
				{Status: "unknown"},
				{Status: "passing"},
			},
			activeControls:  4,
			expectedScore:   50,
			expectedPassing: 2,
			expectedFailing: 1,
			expectedUnknown: 1,
		},
		{
			name:            "no results",
			controlResults:  []osqueryv1alpha1.ControlResult{},
			activeControls:  3,
			expectedScore:   0,
			expectedPassing: 0,
			expectedFailing: 0,
			expectedUnknown: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passing := 0
			failing := 0
			unknown := 0

			for _, cr := range tt.controlResults {
				switch cr.Status {
				case "passing":
					passing++
				case "failing":
					failing++
				default:
					unknown++
				}
			}

			var score int
			if tt.activeControls > 0 && len(tt.controlResults) > 0 {
				score = (passing * 100) / tt.activeControls
			}

			assert.Equal(t, tt.expectedScore, score)
			assert.Equal(t, tt.expectedPassing, passing)
			assert.Equal(t, tt.expectedFailing, failing)
			assert.Equal(t, tt.expectedUnknown, unknown)
		})
	}
}
