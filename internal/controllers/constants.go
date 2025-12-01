package controllers

const (
	AnnotationConfigHash       = "osquery.burdz.net/config-hash"
	AnnotationDistributedQuery = "osquery.burdz.net/distributed-query"
	AnnotationOwnerName        = "osquery.burdz.net/owner-name"
	AnnotationRetention        = "osquery.burdz.net/retention"

	LabelName      = "app.kubernetes.io/name"
	LabelInstance  = "app.kubernetes.io/instance"
	LabelManagedBy = "app.kubernetes.io/managed-by"

	LabelValueName      = "osquery"
	LabelValueManagedBy = "osquery-operator"
)
