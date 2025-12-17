package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FileIntegrityPolicySpec defines the desired state of FileIntegrityPolicy
type FileIntegrityPolicySpec struct {
	// Paths to monitor using fnmatch-style patterns (%, %%)
	// +kubebuilder:validation:MinItems=1
	Paths []string `json:"paths"`

	// Exclude patterns to ignore from monitoring
	// +optional
	Exclude []string `json:"exclude,omitempty"`

	// Accesses enables file access monitoring for this category (Linux only)
	// +optional
	Accesses []string `json:"accesses,omitempty"`

	// Category groups these paths in osquery config (defaults to policy name)
	// +optional
	Category string `json:"category,omitempty"`

	// Interval in seconds between file_events query executions
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:default=300
	// +optional
	Interval int `json:"interval,omitempty"`

	// NodeSelector targets specific nodes for this FIM policy
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Severity for file integrity events from this policy
	// +kubebuilder:validation:Enum=info;low;medium;high;critical
	// +kubebuilder:default="medium"
	// +optional
	Severity string `json:"severity,omitempty"`

	// Disabled allows temporarily disabling this FIM policy
	// +kubebuilder:default=false
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// FileIntegrityPolicyStatus defines the observed state of FileIntegrityPolicy
type FileIntegrityPolicyStatus struct {
	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// DeployedToAgents lists OsqueryAgents where this policy is active
	DeployedToAgents []string `json:"deployedToAgents,omitempty"`

	// PathCount is the number of paths being monitored
	PathCount int `json:"pathCount,omitempty"`

	// LastUpdated is when the policy was last reconciled
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=fip
// +kubebuilder:printcolumn:name="Paths",type="integer",JSONPath=".status.pathCount"
// +kubebuilder:printcolumn:name="Severity",type="string",JSONPath=".spec.severity"
// +kubebuilder:printcolumn:name="Disabled",type="boolean",JSONPath=".spec.disabled"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FileIntegrityPolicy is the Schema for the fileintegritypolicies API
type FileIntegrityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   FileIntegrityPolicySpec   `json:"spec"`
	Status FileIntegrityPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FileIntegrityPolicyList contains a list of FileIntegrityPolicy
type FileIntegrityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []FileIntegrityPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FileIntegrityPolicy{}, &FileIntegrityPolicyList{})
}
