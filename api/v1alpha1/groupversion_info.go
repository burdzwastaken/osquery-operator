// Package v1alpha1 contains API Schema definitions for the osquery v1alpha1 API group.
//
// This package defines the following custom resources:
//   - OsqueryAgent: Deploys osquery as a DaemonSet across cluster nodes
//   - OsqueryPack: Defines query packs with scheduled SQL queries
//   - OsqueryAlert: Configures alerting rules for query results
//   - DistributedQuery: Runs ad-hoc queries across targeted nodes
//   - QueryResult: Stores query results for analysis and alerting
//
// +kubebuilder:object:generate=true
// +groupName=osquery.burdz.net
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the API group and version for osquery resources.
	GroupVersion = schema.GroupVersion{Group: "osquery.burdz.net", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
