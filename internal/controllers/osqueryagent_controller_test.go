package controllers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

func TestGenerateConfig(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Flags: map[string]string{
				"config_refresh":       "300",
				"distributed_interval": "60",
			},
		},
	}

	packs := []osqueryv1alpha1.OsqueryPack{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "security-baseline",
			},
			Spec: osqueryv1alpha1.OsqueryPackSpec{
				Platform: "linux",
				Queries: []osqueryv1alpha1.PackQuery{
					{
						Name:        "listening_ports",
						Query:       "SELECT * FROM listening_ports;",
						Interval:    60,
						Severity:    "info",
						Description: "All listening ports",
					},
					{
						Name:     "disabled_query",
						Query:    "SELECT * FROM disabled;",
						Interval: 60,
						Disabled: true,
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "incident-response",
			},
			Spec: osqueryv1alpha1.OsqueryPackSpec{
				Platform: "linux",
				Disabled: false,
				Queries: []osqueryv1alpha1.PackQuery{
					{
						Name:     "processes",
						Query:    "SELECT * FROM processes WHERE on_disk = 0;",
						Interval: 30,
						Snapshot: true,
						Severity: "critical",
					},
				},
			},
		},
	}

	config, err := r.generateConfig(agent, packs, nil)
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Equal(t, "300", config.Options["config_refresh"])
	assert.Equal(t, "60", config.Options["distributed_interval"])

	assert.Equal(t, "filesystem", config.Options["logger_plugin"])
	assert.Equal(t, "/var/log/osquery", config.Options["logger_path"])
	assert.Equal(t, true, config.Options["logger_rotate"])

	assert.Len(t, config.Packs, 2)

	secPack, ok := config.Packs["security-baseline"]
	require.True(t, ok, "security-baseline pack should exist")
	assert.Equal(t, "linux", secPack.Platform)
	assert.Len(t, secPack.Queries, 1)

	listeningPorts, ok := secPack.Queries["listening_ports"]
	require.True(t, ok)
	assert.Equal(t, "SELECT * FROM listening_ports;", listeningPorts.Query)
	assert.Equal(t, 60, listeningPorts.Interval)
	assert.Equal(t, "All listening ports", listeningPorts.Description)

	irPack, ok := config.Packs["incident-response"]
	require.True(t, ok, "incident-response pack should exist")
	assert.Len(t, irPack.Queries, 1)

	processes, ok := irPack.Queries["processes"]
	require.True(t, ok)
	assert.True(t, processes.Snapshot)
	assert.Equal(t, 30, processes.Interval)

	assert.Contains(t, config.Decorators, "load")
	assert.Len(t, config.Decorators["load"], 2)
}

func TestGenerateConfigJSON(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{},
	}

	packs := []osqueryv1alpha1.OsqueryPack{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pack",
			},
			Spec: osqueryv1alpha1.OsqueryPackSpec{
				Queries: []osqueryv1alpha1.PackQuery{
					{
						Name:     "test_query",
						Query:    "SELECT 1;",
						Interval: 60,
					},
				},
			},
		},
	}

	config, err := r.generateConfig(agent, packs, nil)
	require.NoError(t, err)

	jsonBytes, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	assert.NotEmpty(t, jsonBytes)

	var parsed OsqueryConfig
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err)

	assert.Equal(t, config.Options["logger_plugin"], parsed.Options["logger_plugin"])
}

func TestGenerateConfigEmptyPacks(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Flags: map[string]string{
				"verbose": "true",
			},
		},
	}

	config, err := r.generateConfig(agent, []osqueryv1alpha1.OsqueryPack{}, nil)
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Empty(t, config.Packs)
	assert.Equal(t, "true", config.Options["verbose"])
}

func TestMatchesNodeSelector(t *testing.T) {
	tests := []struct {
		name       string
		nodeLabels map[string]string
		selector   map[string]string
		expected   bool
	}{
		{
			name:       "nil selector matches all",
			nodeLabels: map[string]string{"kubernetes.io/os": "linux"},
			selector:   nil,
			expected:   true,
		},
		{
			name:       "empty selector matches all",
			nodeLabels: map[string]string{"kubernetes.io/os": "linux"},
			selector:   map[string]string{},
			expected:   true,
		},
		{
			name:       "exact match",
			nodeLabels: map[string]string{"kubernetes.io/os": "linux", "node-role": "worker"},
			selector:   map[string]string{"kubernetes.io/os": "linux"},
			expected:   true,
		},
		{
			name:       "multiple selectors - all match",
			nodeLabels: map[string]string{"kubernetes.io/os": "linux", "node-role": "worker"},
			selector:   map[string]string{"kubernetes.io/os": "linux", "node-role": "worker"},
			expected:   true,
		},
		{
			name:       "selector key missing",
			nodeLabels: map[string]string{"kubernetes.io/os": "linux"},
			selector:   map[string]string{"node-role": "worker"},
			expected:   false,
		},
		{
			name:       "selector value mismatch",
			nodeLabels: map[string]string{"kubernetes.io/os": "windows"},
			selector:   map[string]string{"kubernetes.io/os": "linux"},
			expected:   false,
		},
		{
			name:       "empty node labels with selector",
			nodeLabels: map[string]string{},
			selector:   map[string]string{"kubernetes.io/os": "linux"},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesNodeSelector(tt.nodeLabels, tt.selector)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildDaemonSet(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-agent",
			Namespace: "osquery-system",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Image:           "osquery/osquery:5.12.1",
			ImagePullPolicy: corev1.PullIfNotPresent,
			NodeSelector: map[string]string{
				"kubernetes.io/os": "linux",
			},
			Tolerations: []corev1.Toleration{
				{
					Operator: corev1.TolerationOpExists,
				},
			},
		},
	}

	configHash := "abc123"
	ds := r.buildDaemonSet(agent, configHash)

	assert.Equal(t, "test-agent-osquery", ds.Name)
	assert.Equal(t, "osquery-system", ds.Namespace)

	assert.Equal(t, LabelValueName, ds.Labels[LabelName])
	assert.Equal(t, "test-agent", ds.Labels[LabelInstance])

	podSpec := ds.Spec.Template.Spec
	assert.True(t, podSpec.HostPID)
	assert.True(t, podSpec.HostNetwork)
	assert.Equal(t, map[string]string{"kubernetes.io/os": "linux"}, podSpec.NodeSelector)
	assert.Len(t, podSpec.Tolerations, 1)

	assert.Len(t, podSpec.Containers, 2)

	osqueryContainer := podSpec.Containers[0]
	assert.Equal(t, "osquery", osqueryContainer.Name)
	assert.Equal(t, "osquery/osquery:5.12.1", osqueryContainer.Image)
	assert.True(t, *osqueryContainer.SecurityContext.Privileged)

	eventBridgeContainer := podSpec.Containers[1]
	assert.Equal(t, "k8s-event-bridge", eventBridgeContainer.Name)

	assert.Len(t, podSpec.Volumes, 5)

	volumeNames := make([]string, len(podSpec.Volumes))
	for i, v := range podSpec.Volumes {
		volumeNames[i] = v.Name
	}
	assert.Contains(t, volumeNames, "config")
	assert.Contains(t, volumeNames, "logs")
	assert.Contains(t, volumeNames, "host-root")
	assert.Contains(t, volumeNames, "proc")
	assert.Contains(t, volumeNames, "var-run")

	assert.Equal(t, configHash, ds.Spec.Template.Annotations[AnnotationConfigHash])
}

func TestBuildDaemonSetWithResources(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Image: "osquery/osquery:5.12.1",
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    mustParseQuantity("500m"),
					corev1.ResourceMemory: mustParseQuantity("256Mi"),
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    mustParseQuantity("100m"),
					corev1.ResourceMemory: mustParseQuantity("64Mi"),
				},
			},
			EventBridgeResources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    mustParseQuantity("100m"),
					corev1.ResourceMemory: mustParseQuantity("64Mi"),
				},
			},
		},
	}

	ds := r.buildDaemonSet(agent, "hash")

	osqueryContainer := ds.Spec.Template.Spec.Containers[0]
	assert.True(t, osqueryContainer.Resources.Limits[corev1.ResourceCPU].Equal(mustParseQuantity("500m")))
	assert.True(t, osqueryContainer.Resources.Limits[corev1.ResourceMemory].Equal(mustParseQuantity("256Mi")))
	assert.True(t, osqueryContainer.Resources.Requests[corev1.ResourceCPU].Equal(mustParseQuantity("100m")))
	assert.True(t, osqueryContainer.Resources.Requests[corev1.ResourceMemory].Equal(mustParseQuantity("64Mi")))

	eventBridgeContainer := ds.Spec.Template.Spec.Containers[1]
	assert.True(t, eventBridgeContainer.Resources.Limits[corev1.ResourceCPU].Equal(mustParseQuantity("100m")))
	assert.True(t, eventBridgeContainer.Resources.Limits[corev1.ResourceMemory].Equal(mustParseQuantity("64Mi")))
}

func TestBuildDaemonSetVolumeMounts(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Image: "osquery/osquery:5.12.1",
		},
	}

	ds := r.buildDaemonSet(agent, "hash")

	osqueryContainer := ds.Spec.Template.Spec.Containers[0]

	mountPaths := make(map[string]corev1.VolumeMount)
	for _, vm := range osqueryContainer.VolumeMounts {
		mountPaths[vm.Name] = vm
	}

	configMount := mountPaths["config"]
	assert.Equal(t, "/etc/osquery", configMount.MountPath)
	assert.True(t, configMount.ReadOnly)

	hostRootMount := mountPaths["host-root"]
	assert.Equal(t, "/host", hostRootMount.MountPath)
	assert.True(t, hostRootMount.ReadOnly)

	logsMount := mountPaths["logs"]
	assert.Equal(t, "/var/log/osquery", logsMount.MountPath)
	assert.False(t, logsMount.ReadOnly)
}

func TestOsqueryCommand(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Image: "osquery/osquery:5.12.1",
		},
	}

	ds := r.buildDaemonSet(agent, "hash")
	osqueryContainer := ds.Spec.Template.Spec.Containers[0]

	assert.Equal(t, "osqueryd", osqueryContainer.Command[0])
	assert.Contains(t, osqueryContainer.Command, "--config_path=/etc/osquery/osquery.conf")
	assert.Contains(t, osqueryContainer.Command, "--logger_path=/var/log/osquery")
	assert.Contains(t, osqueryContainer.Command, "--pidfile=/var/run/osquery.pid")
	assert.Contains(t, osqueryContainer.Command, "--database_path=/var/osquery/osquery.db")
}

func mustParseQuantity(s string) resource.Quantity {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		panic(err)
	}
	return q
}

func TestGetMatchingPacksFiltersDisabled(t *testing.T) {
	packs := []osqueryv1alpha1.OsqueryPack{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "enabled-pack"},
			Spec:       osqueryv1alpha1.OsqueryPackSpec{Disabled: false},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "disabled-pack"},
			Spec:       osqueryv1alpha1.OsqueryPackSpec{Disabled: true},
		},
	}

	var activePacks []osqueryv1alpha1.OsqueryPack
	for _, pack := range packs {
		if !pack.Spec.Disabled {
			activePacks = append(activePacks, pack)
		}
	}

	assert.Len(t, activePacks, 1)
	assert.Equal(t, "enabled-pack", activePacks[0].Name)
}

func TestBuildDaemonSetStdoutLogging(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-agent",
			Namespace: "osquery-system",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Image: "osquery/osquery:5.12.1",
			Flags: map[string]string{
				"logger_plugin": "stdout",
			},
		},
	}

	ds := r.buildDaemonSet(agent, "hash")
	podSpec := ds.Spec.Template.Spec

	assert.Len(t, podSpec.Containers, 1)
	assert.Equal(t, "osquery", podSpec.Containers[0].Name)

	volumeNames := make([]string, len(podSpec.Volumes))
	for i, v := range podSpec.Volumes {
		volumeNames[i] = v.Name
	}
	assert.NotContains(t, volumeNames, "logs")

	osqueryCommand := podSpec.Containers[0].Command
	assert.NotContains(t, osqueryCommand, "--logger_path=/var/log/osquery")
}

func TestBuildDaemonSetTLSLogging(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-agent",
			Namespace: "osquery-system",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Image: "osquery/osquery:5.12.1",
			Flags: map[string]string{
				"logger_plugin":       "tls",
				"logger_tls_endpoint": "/api/v1/log",
			},
		},
	}

	ds := r.buildDaemonSet(agent, "hash")
	podSpec := ds.Spec.Template.Spec

	assert.Len(t, podSpec.Containers, 1)
	assert.Equal(t, "osquery", podSpec.Containers[0].Name)
}

func TestBuildDaemonSetEventBridgeDisabled(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-agent",
			Namespace: "osquery-system",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Image: "osquery/osquery:5.12.1",
			EventBridge: &osqueryv1alpha1.EventBridgeSpec{
				Enabled: false,
			},
		},
	}

	ds := r.buildDaemonSet(agent, "hash")
	podSpec := ds.Spec.Template.Spec

	assert.Len(t, podSpec.Containers, 1)
	assert.Equal(t, "osquery", podSpec.Containers[0].Name)
}

func TestGenerateConfigStdoutLogging(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Flags: map[string]string{
				"logger_plugin": "stdout",
			},
		},
	}

	config, err := r.generateConfig(agent, []osqueryv1alpha1.OsqueryPack{}, nil)
	require.NoError(t, err)

	assert.Equal(t, "stdout", config.Options["logger_plugin"])
	_, hasLoggerPath := config.Options["logger_path"]
	assert.False(t, hasLoggerPath)
	_, hasLoggerRotate := config.Options["logger_rotate"]
	assert.False(t, hasLoggerRotate)
}

func TestGenerateConfigFilesystemLoggingWithRotation(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{},
	}

	config, err := r.generateConfig(agent, []osqueryv1alpha1.OsqueryPack{}, nil)
	require.NoError(t, err)

	assert.Equal(t, "filesystem", config.Options["logger_plugin"])
	assert.Equal(t, "/var/log/osquery", config.Options["logger_path"])
	assert.Equal(t, true, config.Options["logger_rotate"])
	assert.Equal(t, 26214400, config.Options["logger_rotate_size"])
	assert.Equal(t, 3, config.Options["logger_rotate_max_files"])
}

func TestGenerateConfigCustomLoggerPlugin(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{
			Flags: map[string]string{
				"logger_plugin":      "aws_kinesis",
				"aws_kinesis_stream": "osquery-logs",
				"aws_kinesis_region": "us-east-1",
			},
		},
	}

	config, err := r.generateConfig(agent, []osqueryv1alpha1.OsqueryPack{}, nil)
	require.NoError(t, err)

	assert.Equal(t, "aws_kinesis", config.Options["logger_plugin"])
	assert.Equal(t, "osquery-logs", config.Options["aws_kinesis_stream"])
	_, hasLoggerPath := config.Options["logger_path"]
	assert.False(t, hasLoggerPath)
}

func TestConfigHashChangesWithContent(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       osqueryv1alpha1.OsqueryAgentSpec{},
	}

	packs1 := []osqueryv1alpha1.OsqueryPack{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pack1"},
			Spec: osqueryv1alpha1.OsqueryPackSpec{
				Queries: []osqueryv1alpha1.PackQuery{
					{Name: "q1", Query: "SELECT 1;", Interval: 60},
				},
			},
		},
	}

	packs2 := []osqueryv1alpha1.OsqueryPack{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pack1"},
			Spec: osqueryv1alpha1.OsqueryPackSpec{
				Queries: []osqueryv1alpha1.PackQuery{
					{Name: "q1", Query: "SELECT 2;", Interval: 60},
				},
			},
		},
	}

	config1, _ := r.generateConfig(agent, packs1, nil)
	config2, _ := r.generateConfig(agent, packs2, nil)

	json1, _ := json.Marshal(config1)
	json2, _ := json.Marshal(config2)

	assert.NotEqual(t, string(json1), string(json2), "Configs with different queries should produce different JSON")
}

func TestGenerateConfigWithFIM(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{},
	}

	fimPolicies := []osqueryv1alpha1.FileIntegrityPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "critical-binaries",
			},
			Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
				Paths: []string{
					"/usr/bin/sudo",
					"/usr/bin/ssh",
					"/etc/passwd",
				},
				Exclude: []string{
					"/etc/*.swp",
				},
				Interval: 60,
				Severity: "critical",
			},
		},
	}

	config, err := r.generateConfig(agent, nil, fimPolicies)
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Equal(t, true, config.Options["enable_file_events"])

	require.Contains(t, config.FilePaths, "critical-binaries")
	assert.ElementsMatch(t, []string{"/usr/bin/sudo", "/usr/bin/ssh", "/etc/passwd"}, config.FilePaths["critical-binaries"])

	require.Contains(t, config.ExcludePaths, "critical-binaries")
	assert.ElementsMatch(t, []string{"/etc/*.swp"}, config.ExcludePaths["critical-binaries"])

	require.Contains(t, config.Schedule, "file_events")
	assert.Equal(t, "SELECT * FROM file_events;", config.Schedule["file_events"].Query)
	assert.Equal(t, 60, config.Schedule["file_events"].Interval)
}

func TestGenerateConfigWithFIMCategory(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{},
	}

	fimPolicies := []osqueryv1alpha1.FileIntegrityPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-policy",
			},
			Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
				Category: "etc",
				Paths:    []string{"/etc/%%"},
				Interval: 300,
			},
		},
	}

	config, err := r.generateConfig(agent, nil, fimPolicies)
	require.NoError(t, err)

	require.Contains(t, config.FilePaths, "etc")
	assert.NotContains(t, config.FilePaths, "my-policy")
}

func TestGenerateConfigWithFIMAccesses(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{},
	}

	fimPolicies := []osqueryv1alpha1.FileIntegrityPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sensitive-files",
			},
			Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
				Paths:    []string{"/etc/shadow"},
				Accesses: []string{"read"},
				Interval: 60,
			},
		},
	}

	config, err := r.generateConfig(agent, nil, fimPolicies)
	require.NoError(t, err)

	require.NotEmpty(t, config.FileAccesses)
	assert.Contains(t, config.FileAccesses, "sensitive-files")
}

func TestGenerateConfigWithMultipleFIMPolicies(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{},
	}

	fimPolicies := []osqueryv1alpha1.FileIntegrityPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "binaries"},
			Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
				Paths:    []string{"/usr/bin/%%"},
				Interval: 300,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "configs"},
			Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
				Paths:    []string{"/etc/%%"},
				Interval: 60,
			},
		},
	}

	config, err := r.generateConfig(agent, nil, fimPolicies)
	require.NoError(t, err)

	assert.Len(t, config.FilePaths, 2)
	assert.Contains(t, config.FilePaths, "binaries")
	assert.Contains(t, config.FilePaths, "configs")

	// Should use minimum interval
	assert.Equal(t, 60, config.Schedule["file_events"].Interval)
}

func TestGenerateConfigNoFIM(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	agent := &osqueryv1alpha1.OsqueryAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-agent",
		},
		Spec: osqueryv1alpha1.OsqueryAgentSpec{},
	}

	config, err := r.generateConfig(agent, nil, nil)
	require.NoError(t, err)

	_, hasFileEvents := config.Options["enable_file_events"]
	assert.False(t, hasFileEvents)
	assert.Empty(t, config.FilePaths)
	assert.Empty(t, config.ExcludePaths)
	assert.NotContains(t, config.Schedule, "file_events")
}

func TestNodeSelectorOverlaps(t *testing.T) {
	tests := []struct {
		name           string
		agentSelector  map[string]string
		policySelector map[string]string
		expected       bool
	}{
		{
			name:           "both empty",
			agentSelector:  map[string]string{},
			policySelector: map[string]string{},
			expected:       true,
		},
		{
			name:           "policy empty",
			agentSelector:  map[string]string{"os": "linux"},
			policySelector: map[string]string{},
			expected:       true,
		},
		{
			name:           "exact match",
			agentSelector:  map[string]string{"os": "linux"},
			policySelector: map[string]string{"os": "linux"},
			expected:       true,
		},
		{
			name:           "agent superset",
			agentSelector:  map[string]string{"os": "linux", "role": "worker"},
			policySelector: map[string]string{"os": "linux"},
			expected:       true,
		},
		{
			name:           "policy has extra key",
			agentSelector:  map[string]string{"os": "linux"},
			policySelector: map[string]string{"os": "linux", "fim": "enabled"},
			expected:       true,
		},
		{
			name:           "value mismatch",
			agentSelector:  map[string]string{"os": "windows"},
			policySelector: map[string]string{"os": "linux"},
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nodeSelectorOverlaps(tt.agentSelector, tt.policySelector)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPackMatchesAgent(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	tests := []struct {
		name     string
		pack     *osqueryv1alpha1.OsqueryPack
		agent    *osqueryv1alpha1.OsqueryAgent
		expected bool
	}{
		{
			name: "nil selector matches all packs",
			pack: &osqueryv1alpha1.OsqueryPack{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-pack",
					Labels: map[string]string{"team": "security"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					PackSelector: nil,
				},
			},
			expected: true,
		},
		{
			name: "matching label selector",
			pack: &osqueryv1alpha1.OsqueryPack{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-pack",
					Labels: map[string]string{"osquery.burdz.net/enabled": "true"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					PackSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"osquery.burdz.net/enabled": "true"},
					},
				},
			},
			expected: true,
		},
		{
			name: "non-matching label selector",
			pack: &osqueryv1alpha1.OsqueryPack{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-pack",
					Labels: map[string]string{"osquery.burdz.net/enabled": "false"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					PackSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"osquery.burdz.net/enabled": "true"},
					},
				},
			},
			expected: false,
		},
		{
			name: "pack without labels doesn't match selector",
			pack: &osqueryv1alpha1.OsqueryPack{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pack",
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					PackSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"osquery.burdz.net/enabled": "true"},
					},
				},
			},
			expected: false,
		},
		{
			name: "multiple labels all match",
			pack: &osqueryv1alpha1.OsqueryPack{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-pack",
					Labels: map[string]string{"team": "security", "env": "prod"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					PackSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"team": "security", "env": "prod"},
					},
				},
			},
			expected: true,
		},
		{
			name: "multiple labels partial match fails",
			pack: &osqueryv1alpha1.OsqueryPack{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-pack",
					Labels: map[string]string{"team": "security"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					PackSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"team": "security", "env": "prod"},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.packMatchesAgent(tt.pack, tt.agent)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFIMPolicyMatchesAgent(t *testing.T) {
	r := &OsqueryAgentReconciler{}

	tests := []struct {
		name     string
		policy   *osqueryv1alpha1.FileIntegrityPolicy
		agent    *osqueryv1alpha1.OsqueryAgent
		expected bool
	}{
		{
			name: "disabled policy never matches",
			policy: &osqueryv1alpha1.FileIntegrityPolicy{
				Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
					Disabled: true,
					Paths:    []string{"/etc/passwd"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{},
			},
			expected: false,
		},
		{
			name: "policy without nodeSelector matches all agents",
			policy: &osqueryv1alpha1.FileIntegrityPolicy{
				Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
					Paths: []string{"/etc/passwd"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					NodeSelector: map[string]string{"os": "linux"},
				},
			},
			expected: true,
		},
		{
			name: "agent without nodeSelector matches all policies",
			policy: &osqueryv1alpha1.FileIntegrityPolicy{
				Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
					Paths:        []string{"/etc/passwd"},
					NodeSelector: map[string]string{"os": "linux"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{},
			},
			expected: true,
		},
		{
			name: "overlapping nodeSelectors match",
			policy: &osqueryv1alpha1.FileIntegrityPolicy{
				Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
					Paths:        []string{"/etc/passwd"},
					NodeSelector: map[string]string{"os": "linux"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					NodeSelector: map[string]string{"os": "linux"},
				},
			},
			expected: true,
		},
		{
			name: "conflicting nodeSelectors don't match",
			policy: &osqueryv1alpha1.FileIntegrityPolicy{
				Spec: osqueryv1alpha1.FileIntegrityPolicySpec{
					Paths:        []string{"/etc/passwd"},
					NodeSelector: map[string]string{"os": "windows"},
				},
			},
			agent: &osqueryv1alpha1.OsqueryAgent{
				Spec: osqueryv1alpha1.OsqueryAgentSpec{
					NodeSelector: map[string]string{"os": "linux"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.fimPolicyMatchesAgent(tt.policy, tt.agent)
			assert.Equal(t, tt.expected, result)
		})
	}
}
