package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DistributedQuerySpec defines the desired state of DistributedQuery
type DistributedQuerySpec struct {
	// Query is the SQL query to execute
	Query string `json:"query"`

	// NodeSelector targets specific nodes (empty = all nodes)
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// AgentRef references which OsqueryAgent to use
	// +optional
	AgentRef string `json:"agentRef,omitempty"`

	// Timeout for query execution per node
	// +kubebuilder:default="60s"
	Timeout string `json:"timeout,omitempty"`

	// TTL auto-deletes this query after completion
	// +kubebuilder:default="1h"
	TTL string `json:"ttl,omitempty"`

	// Cardinality limits the number of rows per node
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	// +kubebuilder:default=1000
	Cardinality int `json:"cardinality,omitempty"`
}

// DistributedQueryStatus defines the observed state of DistributedQuery
type DistributedQueryStatus struct {
	// Phase of the distributed query: Pending, Running, Completed, Failed
	// +kubebuilder:validation:Enum=Pending;Running;Completed;Failed;TimedOut
	Phase string `json:"phase,omitempty"`

	// TargetNodes is the number of nodes targeted
	TargetNodes int `json:"targetNodes,omitempty"`

	// CompletedNodes is the number of nodes that have responded
	CompletedNodes int `json:"completedNodes,omitempty"`

	// FailedNodes is the number of nodes that failed to respond
	FailedNodes int `json:"failedNodes,omitempty"`

	// StartTime when the query was dispatched
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime when all nodes responded (or timed out)
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// TotalRows across all nodes
	TotalRows int `json:"totalRows,omitempty"`

	// NodeResults contains per-node result summaries
	NodeResults []NodeQueryResult `json:"nodeResults,omitempty"`

	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NodeQueryResult contains results from a single node
type NodeQueryResult struct {
	// NodeName is the name of the node
	NodeName string `json:"nodeName"`

	// Status of the query on this node: Pending, Completed, Failed, TimedOut
	Status string `json:"status,omitempty"`

	// RowCount returned by this node
	RowCount int `json:"rowCount,omitempty"`

	// Error message if the query failed
	Error string `json:"error,omitempty"`

	// CompletedAt when this node responded
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// Rows contains the actual query results (if small enough)
	// For large results, these are stored in QueryResult CRs
	// +optional
	Rows []map[string]string `json:"rows,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oqdq;dq
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Completed",type="string",JSONPath=".status.completedNodes"
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".status.targetNodes"
// +kubebuilder:printcolumn:name="Rows",type="integer",JSONPath=".status.totalRows"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// DistributedQuery is the Schema for ad-hoc queries across nodes
type DistributedQuery struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   DistributedQuerySpec   `json:"spec"`
	Status DistributedQueryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DistributedQueryList contains a list of DistributedQuery
type DistributedQueryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []DistributedQuery `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DistributedQuery{}, &DistributedQueryList{})
}
