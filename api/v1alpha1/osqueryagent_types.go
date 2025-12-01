package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OsqueryAgentSpec defines the desired state of OsqueryAgent
type OsqueryAgentSpec struct {
	// TargetNamespace is the namespace where the DaemonSet and ConfigMap will be created.
	// Since OsqueryAgent is a cluster-scoped resource, this field specifies where
	// the namespaced resources (DaemonSet, ConfigMap) should be deployed.
	// +kubebuilder:default="osquery-system"
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// Image is the osquery container image to use
	// +kubebuilder:default="osquery/osquery:5.8.2-ubuntu22.04"
	Image string `json:"image,omitempty"`

	// ImagePullPolicy defines when to pull the image
	// +kubebuilder:default="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// NodeSelector for scheduling osquery pods
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for scheduling osquery pods
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Flags are osquery configuration options passed to osqueryd.
	// These map directly to osquery CLI flags and config options.
	// Common logging-related flags include:
	//   - logger_plugin: filesystem (default), stdout, tls, aws_firehose, aws_kinesis, kafka, syslog
	//   - logger_path: path for filesystem logger (default: /var/log/osquery)
	//   - logger_tls_endpoint: endpoint for TLS logger
	// See https://osquery.readthedocs.io/en/stable/installation/cli-flags/ for all options.
	// +optional
	Flags map[string]string `json:"flags,omitempty"`

	// PackSelector selects which OsqueryPacks to deploy
	// +optional
	PackSelector *metav1.LabelSelector `json:"packSelector,omitempty"`

	// EventBridge configures the k8s-event-bridge sidecar which creates
	// Kubernetes Events and QueryResult CRs from osquery results.
	// The sidecar is only deployed when using filesystem logging (the default).
	// Set enabled: false to disable the sidecar, or use a different logger_plugin
	// in Flags to use osquery's native logging (tls, kafka, aws_kinesis, etc).
	// +optional
	EventBridge *EventBridgeSpec `json:"eventBridge,omitempty"`

	// Resources for the osquery container
	// +optional
	Resources corev1.ResourceRequirements `json:"resources"`

	// EventBridgeResources for the k8s-event-bridge sidecar
	// +optional
	EventBridgeResources corev1.ResourceRequirements `json:"eventBridgeResources"`
}

// EventBridgeSpec configures the k8s-event-bridge sidecar
type EventBridgeSpec struct {
	// Enabled controls whether to run the k8s-event-bridge sidecar
	// Only applicable when LoggingMode is "filesystem"
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Image is the k8s-event-bridge container image
	// +kubebuilder:default="ghcr.io/burdzwastaken/osquery-k8s-event-bridge:latest"
	Image string `json:"image,omitempty"`

	// CreateEvents emits K8s Events for query results
	// +kubebuilder:default=true
	CreateEvents bool `json:"createEvents,omitempty"`

	// CreateQueryResults creates QueryResult CRs for results
	// +kubebuilder:default=false
	CreateQueryResults bool `json:"createQueryResults,omitempty"`

	// ResultRetention is how long to keep QueryResult CRs
	// +kubebuilder:default="24h"
	ResultRetention string `json:"resultRetention,omitempty"`
}

// OsqueryAgentStatus defines the observed state of OsqueryAgent
type OsqueryAgentStatus struct {
	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// DesiredNodes is the number of nodes that should run osquery
	DesiredNodes int32 `json:"desiredNodes,omitempty"`

	// ReadyNodes is the number of nodes with healthy osquery
	ReadyNodes int32 `json:"readyNodes,omitempty"`

	// ConfigHash is the hash of the current deployed config
	ConfigHash string `json:"configHash,omitempty"`

	// LastConfigUpdate is when the config was last updated
	LastConfigUpdate *metav1.Time `json:"lastConfigUpdate,omitempty"`

	// AppliedPacks lists the packs currently deployed
	AppliedPacks []string `json:"appliedPacks,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=oqa
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.readyNodes"
// +kubebuilder:printcolumn:name="Desired",type="string",JSONPath=".status.desiredNodes"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// OsqueryAgent is the Schema for the osqueryagents API
type OsqueryAgent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   OsqueryAgentSpec   `json:"spec"`
	Status OsqueryAgentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OsqueryAgentList contains a list of OsqueryAgent
type OsqueryAgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []OsqueryAgent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OsqueryAgent{}, &OsqueryAgentList{})
}
