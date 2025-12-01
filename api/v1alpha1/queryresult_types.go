package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// QueryResultSpec defines the desired state of QueryResult
type QueryResultSpec struct {
	// QueryName that produced this result
	QueryName string `json:"queryName"`

	// PackName if this came from a pack (empty for distributed queries)
	// +optional
	PackName string `json:"packName,omitempty"`

	// DistributedQueryRef if this came from a distributed query
	// +optional
	DistributedQueryRef string `json:"distributedQueryRef,omitempty"`

	// NodeName where the query ran
	NodeName string `json:"nodeName"`

	// Timestamp when the query executed
	Timestamp metav1.Time `json:"timestamp"`

	// Action: added, removed, snapshot
	// +kubebuilder:validation:Enum=added;removed;snapshot
	Action string `json:"action"`

	// Rows contains the query results
	Rows []map[string]string `json:"rows"`

	// Decorations from osquery (host info, etc)
	// +optional
	Decorations map[string]string `json:"decorations,omitempty"`
}

// QueryResultStatus defines the observed state of QueryResult
type QueryResultStatus struct {
	// Severity calculated for this result
	// +kubebuilder:validation:Enum=info;low;medium;high;critical
	Severity string `json:"severity,omitempty"`

	// Acknowledged marks if this result has been reviewed
	Acknowledged bool `json:"acknowledged,omitempty"`

	// AcknowledgedBy user who acknowledged
	// +optional
	AcknowledgedBy string `json:"acknowledgedBy,omitempty"`

	// AcknowledgedAt time of acknowledgement
	// +optional
	AcknowledgedAt *metav1.Time `json:"acknowledgedAt,omitempty"`

	// AlertsFired lists alerts triggered by this result
	// +optional
	AlertsFired []string `json:"alertsFired,omitempty"`

	// ExpiresAt when this result will be auto-deleted
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oqr;qr
// +kubebuilder:printcolumn:name="Query",type="string",JSONPath=".spec.queryName"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="Severity",type="string",JSONPath=".status.severity"
// +kubebuilder:printcolumn:name="Rows",type="integer",JSONPath=".spec.rows"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// QueryResult stores query results in the cluster
type QueryResult struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   QueryResultSpec   `json:"spec"`
	Status QueryResultStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// QueryResultList contains a list of QueryResult
type QueryResultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []QueryResult `json:"items"`
}

func init() {
	SchemeBuilder.Register(&QueryResult{}, &QueryResultList{})
}
