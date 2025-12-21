package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompliancePolicySpec defines the desired state of CompliancePolicy
type CompliancePolicySpec struct {
	// Framework identifies the compliance framework (e.g., "cis", "pci-dss", "hipaa")
	// +optional
	Framework string `json:"framework,omitempty"`

	// Version of the compliance framework
	// +optional
	Version string `json:"version,omitempty"`

	// Controls defines the individual compliance checks
	// +kubebuilder:validation:MinItems=1
	Controls []ComplianceControl `json:"controls"`

	// NodeSelector targets specific nodes for compliance checks
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Platform restricts this policy to specific platforms
	// +kubebuilder:validation:Enum=linux;darwin;windows
	// +kubebuilder:default="linux"
	// +optional
	Platform string `json:"platform,omitempty"`

	// Disabled allows temporarily disabling this compliance policy
	// +kubebuilder:default=false
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// ComplianceControl defines a single compliance check
type ComplianceControl struct {
	// ID is the unique identifier for this control (e.g., "5.1.1")
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`

	// Title is a short description of the control
	// +kubebuilder:validation:MinLength=1
	Title string `json:"title"`

	// Description provides detailed information about the control
	// +optional
	Description string `json:"description,omitempty"`

	// Query is the osquery SQL to execute for this control
	// +kubebuilder:validation:MinLength=1
	Query string `json:"query"`

	// Interval in seconds between query executions
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:default=3600
	Interval int `json:"interval,omitempty"`

	// Severity of a failing control
	// +kubebuilder:validation:Enum=info;low;medium;high;critical
	// +kubebuilder:default="medium"
	// +optional
	Severity string `json:"severity,omitempty"`

	// Remediation describes how to fix a failing control
	// +optional
	Remediation string `json:"remediation,omitempty"`

	// Expectation defines what constitutes a passing result
	// +optional
	Expectation *ControlExpectation `json:"expectation,omitempty"`

	// Disabled allows temporarily disabling this control
	// +kubebuilder:default=false
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// ControlExpectation defines the pass/fail criteria for a control
type ControlExpectation struct {
	// Type of expectation check
	// +kubebuilder:validation:Enum=rowCount
	// +kubebuilder:default="rowCount"
	Type string `json:"type,omitempty"`

	// Operator for the comparison
	// +kubebuilder:validation:Enum=equals;lessThan;greaterThan;lessThanOrEqual;greaterThanOrEqual
	// +kubebuilder:default="equals"
	Operator string `json:"operator,omitempty"`

	// Value to compare against
	// +kubebuilder:default=0
	Value int `json:"value,omitempty"`
}

// CompliancePolicyStatus defines the observed state of CompliancePolicy
type CompliancePolicyStatus struct {
	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Score is the compliance percentage (0-100)
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	Score *int `json:"score,omitempty"`

	// TotalControls is the number of controls in this policy
	TotalControls int `json:"totalControls,omitempty"`

	// PassingControls is the number of controls currently passing
	PassingControls int `json:"passingControls,omitempty"`

	// FailingControls is the number of controls currently failing
	FailingControls int `json:"failingControls,omitempty"`

	// UnknownControls is the number of controls with unknown status
	UnknownControls int `json:"unknownControls,omitempty"`

	// ControlResults contains per-control status
	// +optional
	ControlResults []ControlResult `json:"controlResults,omitempty"`

	// GeneratedPackName is the name of the OsqueryPack created for this policy
	// +optional
	GeneratedPackName string `json:"generatedPackName,omitempty"`

	// LastScanTime is when the compliance was last evaluated
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// LastUpdated is when the policy was last reconciled
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`
}

// ControlResult contains the status of a single control
type ControlResult struct {
	// ID matches the control ID
	ID string `json:"id"`

	// Status of the control
	// +kubebuilder:validation:Enum=passing;failing;error;unknown
	Status string `json:"status"`

	// Message provides additional context (especially for errors)
	// +optional
	Message string `json:"message,omitempty"`

	// AffectedNodes lists nodes where this control is failing
	// +optional
	AffectedNodes []string `json:"affectedNodes,omitempty"`

	// RowCount is the number of rows returned by the query
	// +optional
	RowCount *int `json:"rowCount,omitempty"`

	// LastChecked is when this control was last evaluated
	// +optional
	LastChecked *metav1.Time `json:"lastChecked,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cp
// +kubebuilder:printcolumn:name="Framework",type="string",JSONPath=".spec.framework"
// +kubebuilder:printcolumn:name="Score",type="number",JSONPath=".status.score",format="float"
// +kubebuilder:printcolumn:name="Passing",type="integer",JSONPath=".status.passingControls"
// +kubebuilder:printcolumn:name="Failing",type="integer",JSONPath=".status.failingControls"
// +kubebuilder:printcolumn:name="Disabled",type="boolean",JSONPath=".spec.disabled"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// CompliancePolicy is the Schema for the compliancepolicies API
type CompliancePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   CompliancePolicySpec   `json:"spec"`
	Status CompliancePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CompliancePolicyList contains a list of CompliancePolicy
type CompliancePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CompliancePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CompliancePolicy{}, &CompliancePolicyList{})
}
