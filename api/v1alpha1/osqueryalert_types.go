package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OsqueryAlertSpec defines the desired state of OsqueryAlert
type OsqueryAlertSpec struct {
	// QuerySelector matches queries by name or labels
	QuerySelector QuerySelector `json:"querySelector"`

	// Condition that triggers the alert
	Condition AlertCondition `json:"condition"`

	// Severity of this alert
	// +kubebuilder:validation:Enum=info;low;medium;high;critical
	// +kubebuilder:default="medium"
	Severity string `json:"severity,omitempty"`

	// Throttle prevents alert spam
	// +optional
	Throttle *AlertThrottle `json:"throttle,omitempty"`

	// Notify configures alert destinations
	Notify AlertNotify `json:"notify"`

	// Disabled allows temporarily disabling an alert
	// +kubebuilder:default=false
	Disabled bool `json:"disabled,omitempty"`
}

// QuerySelector identifies which queries to evaluate
type QuerySelector struct {
	// QueryName matches a specific query name
	// +optional
	QueryName string `json:"queryName,omitempty"`

	// PackName matches queries from a specific pack
	// +optional
	PackName string `json:"packName,omitempty"`

	// MatchLabels selects queries by labels
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// AlertCondition defines when to fire an alert
type AlertCondition struct {
	// Type of condition: rowMatch, rowCount, fieldThreshold
	// +kubebuilder:validation:Enum=rowMatch;rowCount;fieldThreshold;any
	Type string `json:"type"`

	// RowMatch fires when any row matches all specified field patterns
	// +optional
	RowMatch []FieldMatch `json:"rowMatch,omitempty"`

	// RowCount fires when result count meets threshold
	// +optional
	RowCount *RowCountCondition `json:"rowCount,omitempty"`

	// FieldThreshold fires when a numeric field exceeds threshold
	// +optional
	FieldThreshold *FieldThresholdCondition `json:"fieldThreshold,omitempty"`
}

// FieldMatch defines a pattern to match against a field
type FieldMatch struct {
	// Field name to match
	Field string `json:"field"`

	// Regex pattern to match (mutually exclusive with equals)
	// +optional
	Regex string `json:"regex,omitempty"`

	// Equals exact value match (mutually exclusive with regex)
	// +optional
	Equals string `json:"equals,omitempty"`

	// NotEquals inverts the match
	// +optional
	NotEquals string `json:"notEquals,omitempty"`

	// Contains substring match
	// +optional
	Contains string `json:"contains,omitempty"`
}

// RowCountCondition triggers on number of rows
type RowCountCondition struct {
	// Operator: gt, gte, lt, lte, eq
	// +kubebuilder:validation:Enum=gt;gte;lt;lte;eq
	Operator string `json:"operator"`

	// Value to compare against
	Value int `json:"value"`
}

// FieldThresholdCondition triggers on numeric field values
type FieldThresholdCondition struct {
	// Field name containing numeric value
	Field string `json:"field"`

	// Operator: gt, gte, lt, lte, eq
	// +kubebuilder:validation:Enum=gt;gte;lt;lte;eq
	Operator string `json:"operator"`

	// Value to compare against
	Value int64 `json:"value"`
}

// AlertThrottle prevents alert spam
type AlertThrottle struct {
	// Period to throttle alerts
	// +kubebuilder:default="15m"
	Period string `json:"period,omitempty"`

	// MaxAlerts per period (0 = no limit)
	// +kubebuilder:default=1
	MaxAlerts int `json:"maxAlerts,omitempty"`

	// GroupBy fields to throttle per unique combination
	// +optional
	GroupBy []string `json:"groupBy,omitempty"`
}

// AlertNotify configures alert destinations
type AlertNotify struct {
	// Kubernetes emits K8s Events and/or updates QueryResult status
	// +optional
	Kubernetes *KubernetesNotify `json:"kubernetes,omitempty"`

	// Slack webhook notification
	// +optional
	Slack *SlackNotify `json:"slack,omitempty"`

	// Webhook generic HTTP notification
	// +optional
	Webhook *WebhookNotify `json:"webhook,omitempty"`
}

// KubernetesNotify emits K8s native notifications
type KubernetesNotify struct {
	// CreateEvent emits a K8s Event
	// +kubebuilder:default=true
	CreateEvent bool `json:"createEvent,omitempty"`

	// EventType: Normal or Warning
	// +kubebuilder:validation:Enum=Normal;Warning
	// +kubebuilder:default="Warning"
	EventType string `json:"eventType,omitempty"`
}

// SlackNotify sends to Slack
type SlackNotify struct {
	// WebhookSecretRef references a secret containing the webhook URL
	WebhookSecretRef corev1.SecretReference `json:"webhookSecretRef"`

	// Channel to post to (overrides webhook default)
	// +optional
	Channel string `json:"channel,omitempty"`

	// Username for the bot
	// +optional
	Username string `json:"username,omitempty"`
}

// WebhookNotify sends to generic HTTP endpoint
type WebhookNotify struct {
	// URL to POST to
	URL string `json:"url"`

	// Headers to include
	// +optional
	Headers map[string]string `json:"headers,omitempty"`

	// SecretRef for auth headers
	// +optional
	SecretRef *corev1.SecretReference `json:"secretRef,omitempty"`
}

// OsqueryAlertStatus defines the observed state of OsqueryAlert
type OsqueryAlertStatus struct {
	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastFired when this alert last triggered
	// +optional
	LastFired *metav1.Time `json:"lastFired,omitempty"`

	// FireCount total times this alert has fired
	FireCount int64 `json:"fireCount,omitempty"`

	// ThrottledCount alerts suppressed by throttling
	ThrottledCount int64 `json:"throttledCount,omitempty"`

	// LastEvaluated when the alert was last evaluated
	// +optional
	LastEvaluated *metav1.Time `json:"lastEvaluated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oqal;alert
// +kubebuilder:printcolumn:name="Severity",type="string",JSONPath=".spec.severity"
// +kubebuilder:printcolumn:name="Fired",type="integer",JSONPath=".status.fireCount"
// +kubebuilder:printcolumn:name="Last Fired",type="date",JSONPath=".status.lastFired"
// +kubebuilder:printcolumn:name="Disabled",type="boolean",JSONPath=".spec.disabled"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// OsqueryAlert defines alerting rules for query results
type OsqueryAlert struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   OsqueryAlertSpec   `json:"spec"`
	Status OsqueryAlertStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OsqueryAlertList contains a list of OsqueryAlert
type OsqueryAlertList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []OsqueryAlert `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OsqueryAlert{}, &OsqueryAlertList{})
}
