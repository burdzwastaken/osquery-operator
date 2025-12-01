package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OsqueryPackSpec defines the desired state of OsqueryPack
type OsqueryPackSpec struct {
	// NodeSelector targets specific nodes for this pack
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Queries in this pack
	Queries []PackQuery `json:"queries"`

	// Platform restricts this pack to specific platforms
	// +kubebuilder:validation:Enum=linux;darwin;windows
	// +kubebuilder:default="linux"
	// +optional
	Platform string `json:"platform,omitempty"`

	// Disabled allows temporarily disabling a pack
	// +kubebuilder:default=false
	Disabled bool `json:"disabled,omitempty"`
}

// PackQuery defines a single query within a pack
type PackQuery struct {
	// Name of the query (must be unique within pack)
	Name string `json:"name"`

	// Query is the SQL query to execute
	Query string `json:"query"`

	// Interval in seconds between query executions
	// +kubebuilder:validation:Minimum=10
	Interval int `json:"interval"`

	// Snapshot mode returns all results each time (vs differential)
	// +kubebuilder:default=false
	Snapshot bool `json:"snapshot,omitempty"`

	// Description of what this query does
	// +optional
	Description string `json:"description,omitempty"`

	// Severity for results from this query
	// +kubebuilder:validation:Enum=info;low;medium;high;critical
	// +kubebuilder:default="info"
	// +optional
	Severity string `json:"severity,omitempty"`

	// Disabled allows temporarily disabling a query
	// +kubebuilder:default=false
	Disabled bool `json:"disabled,omitempty"`
}

// OsqueryPackStatus defines the observed state of OsqueryPack
type OsqueryPackStatus struct {
	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// DeployedToNodes lists nodes where this pack is active
	DeployedToNodes []string `json:"deployedToNodes,omitempty"`

	// QueryCount is the number of active queries in this pack
	QueryCount int `json:"queryCount,omitempty"`

	// LastUpdated is when the pack was last reconciled
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oqp
// +kubebuilder:printcolumn:name="Queries",type="integer",JSONPath=".status.queryCount"
// +kubebuilder:printcolumn:name="Nodes",type="integer",JSONPath=".status.deployedToNodes"
// +kubebuilder:printcolumn:name="Disabled",type="boolean",JSONPath=".spec.disabled"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// OsqueryPack is the Schema for the osquerypacks API
type OsqueryPack struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   OsqueryPackSpec   `json:"spec"`
	Status OsqueryPackStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OsqueryPackList contains a list of OsqueryPack
type OsqueryPackList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []OsqueryPack `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OsqueryPack{}, &OsqueryPackList{})
}
