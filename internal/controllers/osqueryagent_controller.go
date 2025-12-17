package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

// OsqueryAgentReconciler reconciles OsqueryAgent resources.
// It creates and manages a DaemonSet running osquery on cluster nodes,
// along with a ConfigMap containing the osquery configuration generated
// from OsqueryPack resources.
type OsqueryAgentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=osquery.burdz.net,resources=osqueryagents,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=osqueryagents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=osqueryagents/finalizers,verbs=update
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=osquerypacks,verbs=get;list;watch
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=fileintegritypolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=fileintegritypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

func getTargetNamespace(agent *osqueryv1alpha1.OsqueryAgent) string {
	if agent.Spec.TargetNamespace != "" {
		return agent.Spec.TargetNamespace
	}
	return "osquery-system"
}

// Reconcile handles OsqueryAgent create/update/delete events. It generates
// osquery configuration from matching OsqueryPack resources and deploys
// a DaemonSet with osquery and optionally the k8s-event-bridge sidecar.
func (r *OsqueryAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	agent := &osqueryv1alpha1.OsqueryAgent{}
	if err := r.Get(ctx, req.NamespacedName, agent); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling OsqueryAgent", "name", agent.Name, "targetNamespace", getTargetNamespace(agent))

	packs, err := r.getMatchingPacks(ctx, agent)
	if err != nil {
		return ctrl.Result{}, err
	}

	fimPolicies, err := r.getMatchingFIMPolicies(ctx, agent)
	if err != nil {
		return ctrl.Result{}, err
	}

	config, err := r.generateConfig(agent, packs, fimPolicies)
	if err != nil {
		return ctrl.Result{}, err
	}

	configHash, err := r.reconcileConfigMap(ctx, agent, config)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileDaemonSet(ctx, agent, configHash); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, agent, packs, configHash); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *OsqueryAgentReconciler) getMatchingPacks(ctx context.Context, agent *osqueryv1alpha1.OsqueryAgent) ([]osqueryv1alpha1.OsqueryPack, error) {
	packList := &osqueryv1alpha1.OsqueryPackList{}

	listOpts := []client.ListOption{}
	if agent.Spec.PackSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(agent.Spec.PackSelector)
		if err != nil {
			return nil, err
		}
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: selector})
	}

	if err := r.List(ctx, packList, listOpts...); err != nil {
		return nil, err
	}

	var activePacks []osqueryv1alpha1.OsqueryPack
	for _, pack := range packList.Items {
		if !pack.Spec.Disabled {
			activePacks = append(activePacks, pack)
		}
	}

	return activePacks, nil
}

func (r *OsqueryAgentReconciler) getMatchingFIMPolicies(ctx context.Context, agent *osqueryv1alpha1.OsqueryAgent) ([]osqueryv1alpha1.FileIntegrityPolicy, error) {
	fimList := &osqueryv1alpha1.FileIntegrityPolicyList{}

	if err := r.List(ctx, fimList); err != nil {
		return nil, err
	}

	var activePolicies []osqueryv1alpha1.FileIntegrityPolicy
	for _, policy := range fimList.Items {
		if policy.Spec.Disabled {
			continue
		}

		if len(policy.Spec.NodeSelector) > 0 {
			if len(agent.Spec.NodeSelector) > 0 {
				if !nodeSelectorOverlaps(agent.Spec.NodeSelector, policy.Spec.NodeSelector) {
					continue
				}
			}
		}

		activePolicies = append(activePolicies, policy)
	}

	return activePolicies, nil
}

func nodeSelectorOverlaps(agentSelector, policySelector map[string]string) bool {
	for k, v := range policySelector {
		if agentVal, ok := agentSelector[k]; ok && agentVal != v {
			return false
		}
	}
	return true
}

// OsqueryConfig represents the osquery JSON configuration file structure.
// See https://osquery.readthedocs.io/en/stable/deployment/configuration/
type OsqueryConfig struct {
	Options      map[string]any           `json:"options,omitempty"`
	Schedule     map[string]ScheduleEntry `json:"schedule,omitempty"`
	Packs        map[string]PackConfig    `json:"packs,omitempty"`
	Decorators   map[string][]string      `json:"decorators,omitempty"`
	FilePaths    map[string][]string      `json:"file_paths,omitempty"`
	ExcludePaths map[string][]string      `json:"exclude_paths,omitempty"`
	FileAccesses []string                 `json:"file_accesses,omitempty"`
}

// ScheduleEntry defines a scheduled query in osquery config.
type ScheduleEntry struct {
	Query    string `json:"query"`
	Interval int    `json:"interval"`
	Snapshot bool   `json:"snapshot,omitempty"`
}

// PackConfig defines a query pack in osquery config.
type PackConfig struct {
	Queries  map[string]PackQueryConfig `json:"queries"`
	Platform string                     `json:"platform,omitempty"`
}

// PackQueryConfig defines a single query within a pack.
type PackQueryConfig struct {
	Query       string `json:"query"`
	Interval    int    `json:"interval"`
	Snapshot    bool   `json:"snapshot,omitempty"`
	Description string `json:"description,omitempty"`
}

func (r *OsqueryAgentReconciler) generateConfig(agent *osqueryv1alpha1.OsqueryAgent, packs []osqueryv1alpha1.OsqueryPack, fimPolicies []osqueryv1alpha1.FileIntegrityPolicy) (*OsqueryConfig, error) {
	config := &OsqueryConfig{
		Options:      make(map[string]any),
		Schedule:     make(map[string]ScheduleEntry),
		Packs:        make(map[string]PackConfig),
		FilePaths:    make(map[string][]string),
		ExcludePaths: make(map[string][]string),
		Decorators: map[string][]string{
			"load": {
				"SELECT uuid AS host_uuid FROM system_info;",
				"SELECT hostname AS hostname FROM system_info;",
			},
		},
	}

	for k, v := range agent.Spec.Flags {
		config.Options[k] = v
	}

	loggerPlugin, ok := config.Options["logger_plugin"].(string)
	if !ok {
		loggerPlugin = "filesystem"
		config.Options["logger_plugin"] = loggerPlugin
	}

	// Set filesystem logging defaults: rotation to prevent disk exhaustion,
	// and 0644 mode so the k8s-event-bridge sidecar can read logs
	if loggerPlugin == "filesystem" {
		if _, ok := config.Options["logger_path"]; !ok {
			config.Options["logger_path"] = "/var/log/osquery"
		}
		if _, ok := config.Options["logger_rotate"]; !ok {
			config.Options["logger_rotate"] = true
		}
		if _, ok := config.Options["logger_rotate_size"]; !ok {
			config.Options["logger_rotate_size"] = 26214400 // 25MB
		}
		if _, ok := config.Options["logger_rotate_max_files"]; !ok {
			config.Options["logger_rotate_max_files"] = 3
		}
		if _, ok := config.Options["logger_mode"]; !ok {
			config.Options["logger_mode"] = 420 // 0644 in decimal
		}
	}

	for _, pack := range packs {
		packConfig := PackConfig{
			Queries:  make(map[string]PackQueryConfig),
			Platform: pack.Spec.Platform,
		}

		for _, query := range pack.Spec.Queries {
			if !query.Disabled {
				packConfig.Queries[query.Name] = PackQueryConfig{
					Query:       query.Query,
					Interval:    query.Interval,
					Snapshot:    query.Snapshot,
					Description: query.Description,
				}
			}
		}

		config.Packs[pack.Name] = packConfig
	}

	if len(fimPolicies) > 0 {
		if _, ok := config.Options["enable_file_events"]; !ok {
			config.Options["enable_file_events"] = true
		}

		var accessCategories []string
		minInterval := 300
		for _, policy := range fimPolicies {
			if policy.Spec.Interval > 0 && policy.Spec.Interval < minInterval {
				minInterval = policy.Spec.Interval
			}
		}

		for _, policy := range fimPolicies {
			category := policy.Spec.Category
			if category == "" {
				category = policy.Name
			}

			if len(policy.Spec.Paths) > 0 {
				config.FilePaths[category] = append(config.FilePaths[category], policy.Spec.Paths...)
			}

			if len(policy.Spec.Exclude) > 0 {
				config.ExcludePaths[category] = append(config.ExcludePaths[category], policy.Spec.Exclude...)
			}

			if len(policy.Spec.Accesses) > 0 {
				accessCategories = append(accessCategories, category)
			}
		}

		if len(accessCategories) > 0 {
			config.FileAccesses = accessCategories
		}

		config.Schedule["file_events"] = ScheduleEntry{
			Query:    "SELECT * FROM file_events;",
			Interval: minInterval,
		}
	}

	return config, nil
}

func (r *OsqueryAgentReconciler) reconcileConfigMap(ctx context.Context, agent *osqueryv1alpha1.OsqueryAgent, config *OsqueryConfig) (string, error) {
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(configJSON))[:16]
	targetNamespace := getTargetNamespace(agent)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-config", agent.Name),
			Namespace: targetNamespace,
			Labels: map[string]string{
				LabelName:      LabelValueName,
				LabelInstance:  agent.Name,
				LabelManagedBy: LabelValueManagedBy,
			},
			Annotations: map[string]string{
				AnnotationOwnerName: agent.Name,
			},
		},
		Data: map[string]string{
			"osquery.conf": string(configJSON),
		},
	}

	found := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		if err := r.Create(ctx, cm); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	} else {
		found.Data = cm.Data
		found.Labels = cm.Labels
		found.Annotations = cm.Annotations
		if err := r.Update(ctx, found); err != nil {
			return "", err
		}
	}

	return hash, nil
}

func (r *OsqueryAgentReconciler) reconcileDaemonSet(ctx context.Context, agent *osqueryv1alpha1.OsqueryAgent, configHash string) error {
	ds := r.buildDaemonSet(agent, configHash)

	found := &appsv1.DaemonSet{}
	err := r.Get(ctx, types.NamespacedName{Name: ds.Name, Namespace: ds.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		return r.Create(ctx, ds)
	} else if err != nil {
		return err
	}

	found.Spec = ds.Spec
	found.Labels = ds.Labels
	found.Annotations = ds.Annotations
	return r.Update(ctx, found)
}

func getLoggerPlugin(flags map[string]string) string {
	if plugin, ok := flags["logger_plugin"]; ok {
		return plugin
	}
	return "filesystem"
}

func usesFilesystemLogging(agent *osqueryv1alpha1.OsqueryAgent) bool {
	return getLoggerPlugin(agent.Spec.Flags) == "filesystem"
}

func (r *OsqueryAgentReconciler) buildDaemonSet(agent *osqueryv1alpha1.OsqueryAgent, configHash string) *appsv1.DaemonSet {
	privileged := true
	hostPID := true
	hostNetwork := true

	labels := map[string]string{
		LabelName:      LabelValueName,
		LabelInstance:  agent.Name,
		LabelManagedBy: LabelValueManagedBy,
	}

	filesystemLogging := usesFilesystemLogging(agent)

	osqueryCommand := []string{
		"osqueryd",
		"--config_path=/etc/osquery/osquery.conf",
		"--pidfile=/var/run/osquery.pid",
		"--database_path=/var/osquery/osquery.db",
	}
	if filesystemLogging {
		osqueryCommand = append(osqueryCommand,
			"--logger_path=/var/log/osquery",
			"--logger_mode=0644",
		)
	}

	osqueryVolumeMounts := []corev1.VolumeMount{
		{
			Name:      "config",
			MountPath: "/etc/osquery",
			ReadOnly:  true,
		},
		{
			Name:      "host-root",
			MountPath: "/host",
			ReadOnly:  true,
		},
		{
			Name:      "proc",
			MountPath: "/host/proc",
			ReadOnly:  true,
		},
		{
			Name:      "var-run",
			MountPath: "/var/run",
		},
	}

	if filesystemLogging {
		osqueryVolumeMounts = append(osqueryVolumeMounts, corev1.VolumeMount{
			Name:      "logs",
			MountPath: "/var/log/osquery",
		})
	}

	containers := []corev1.Container{
		{
			Name:            "osquery",
			Image:           agent.Spec.Image,
			ImagePullPolicy: agent.Spec.ImagePullPolicy,
			Command:         osqueryCommand,
			SecurityContext: &corev1.SecurityContext{
				Privileged: &privileged,
			},
			VolumeMounts: osqueryVolumeMounts,
			Resources:    agent.Spec.Resources,
		},
	}

	if filesystemLogging {
		eventBridgeEnabled := true
		eventBridgeImage := "ghcr.io/burdzwastaken/osquery-k8s-event-bridge:latest"

		if agent.Spec.EventBridge != nil {
			eventBridgeEnabled = agent.Spec.EventBridge.Enabled
			if agent.Spec.EventBridge.Image != "" {
				eventBridgeImage = agent.Spec.EventBridge.Image
			}
		}

		if eventBridgeEnabled {
			containers = append(containers, corev1.Container{
				Name:            "k8s-event-bridge",
				Image:           eventBridgeImage,
				ImagePullPolicy: agent.Spec.ImagePullPolicy,
				Args: []string{
					"--log-path=/var/log/osquery",
				},
				Env: []corev1.EnvVar{
					{
						Name: "NODE_NAME",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "spec.nodeName",
							},
						},
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "logs",
						MountPath: "/var/log/osquery",
						ReadOnly:  true,
					},
				},
				Resources: agent.Spec.EventBridgeResources,
			})
		}
	}

	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-config", agent.Name),
					},
				},
			},
		},
		{
			Name: "host-root",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/",
				},
			},
		},
		{
			Name: "proc",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/proc",
				},
			},
		},
		{
			Name: "var-run",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run",
				},
			},
		},
	}

	if filesystemLogging {
		volumes = append(volumes, corev1.Volume{
			Name: "logs",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-osquery", agent.Name),
			Namespace: getTargetNamespace(agent),
			Labels:    labels,
			Annotations: map[string]string{
				AnnotationOwnerName: agent.Name,
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						AnnotationConfigHash: configHash,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "osquery-agent",
					HostPID:            hostPID,
					HostNetwork:        hostNetwork,
					NodeSelector:       agent.Spec.NodeSelector,
					Tolerations:        agent.Spec.Tolerations,
					Containers:         containers,
					Volumes:            volumes,
				},
			},
		},
	}
}

func (r *OsqueryAgentReconciler) updateStatus(ctx context.Context, agent *osqueryv1alpha1.OsqueryAgent, packs []osqueryv1alpha1.OsqueryPack, configHash string) error {
	nodeList := &corev1.NodeList{}
	if err := r.List(ctx, nodeList); err != nil {
		return err
	}

	desiredNodes := int32(0)
	for _, node := range nodeList.Items {
		if matchesNodeSelector(node.Labels, agent.Spec.NodeSelector) {
			desiredNodes++
		}
	}

	ds := &appsv1.DaemonSet{}
	dsName := types.NamespacedName{
		Name:      fmt.Sprintf("%s-osquery", agent.Name),
		Namespace: getTargetNamespace(agent),
	}
	readyNodes := int32(0)
	if err := r.Get(ctx, dsName, ds); err == nil {
		readyNodes = ds.Status.NumberReady
	}

	packNames := make([]string, len(packs))
	for i, p := range packs {
		packNames[i] = p.Name
	}

	agent.Status.DesiredNodes = desiredNodes
	agent.Status.ReadyNodes = readyNodes
	agent.Status.ConfigHash = configHash
	agent.Status.AppliedPacks = packNames
	now := metav1.Now()
	agent.Status.LastConfigUpdate = &now

	return r.Status().Update(ctx, agent)
}

func matchesNodeSelector(nodeLabels, selector map[string]string) bool {
	if selector == nil {
		return true
	}
	for k, v := range selector {
		if nodeLabels[k] != v {
			return false
		}
	}
	return true
}

// SetupWithManager sets up the controller with the Manager.
func (r *OsqueryAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&osqueryv1alpha1.OsqueryAgent{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}
