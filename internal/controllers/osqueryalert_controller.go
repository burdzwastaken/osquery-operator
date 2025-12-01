package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

// OsqueryAlertReconciler reconciles OsqueryAlert objects
type OsqueryAlertReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	throttleCache map[string][]time.Time
	throttleMu    sync.RWMutex
}

// +kubebuilder:rbac:groups=osquery.burdz.net,resources=osqueryalerts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=osqueryalerts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=osqueryalerts/finalizers,verbs=update
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=queryresults,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *OsqueryAlertReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	alert := &osqueryv1alpha1.OsqueryAlert{}
	if err := r.Get(ctx, req.NamespacedName, alert); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if alert.Spec.Disabled {
		logger.V(1).Info("Alert is disabled, skipping", "name", alert.Name)
		return ctrl.Result{}, nil
	}

	logger.Info("Reconciling OsqueryAlert", "name", alert.Name)

	results, err := r.getMatchingResults(ctx, alert)
	if err != nil {
		return ctrl.Result{}, err
	}

	var triggered bool
	for _, result := range results {
		if r.evaluateCondition(alert, &result) {
			if r.isThrottled(alert, &result) {
				logger.V(1).Info("Alert throttled", "alert", alert.Name, "result", result.Name)
				alert.Status.ThrottledCount++
				continue
			}

			if err := r.fireAlert(ctx, alert, &result); err != nil {
				logger.Error(err, "Failed to fire alert", "alert", alert.Name)
				continue
			}

			triggered = true
			r.recordThrottle(alert, &result)

			if err := r.markResultAlerted(ctx, &result, alert.Name); err != nil {
				logger.Error(err, "Failed to update result status", "result", result.Name)
			}
		}
	}

	now := metav1.Now()
	alert.Status.LastEvaluated = &now
	if triggered {
		alert.Status.LastFired = &now
		alert.Status.FireCount++
	}

	if err := r.Status().Update(ctx, alert); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *OsqueryAlertReconciler) getMatchingResults(ctx context.Context, alert *osqueryv1alpha1.OsqueryAlert) ([]osqueryv1alpha1.QueryResult, error) {
	resultList := &osqueryv1alpha1.QueryResultList{}

	listOpts := []client.ListOption{
		client.InNamespace(alert.Namespace),
	}

	if err := r.List(ctx, resultList, listOpts...); err != nil {
		return nil, err
	}

	var matched []osqueryv1alpha1.QueryResult
	for _, result := range resultList.Items {
		if result.Status.Acknowledged {
			continue
		}

		if slices.Contains(result.Status.AlertsFired, alert.Name) {
			continue
		}

		if alert.Spec.QuerySelector.QueryName != "" {
			if result.Spec.QueryName != alert.Spec.QuerySelector.QueryName {
				continue
			}
		}

		if alert.Spec.QuerySelector.PackName != "" {
			if result.Spec.PackName != alert.Spec.QuerySelector.PackName {
				continue
			}
		}

		if len(alert.Spec.QuerySelector.MatchLabels) > 0 {
			if !labelsMatch(result.Labels, alert.Spec.QuerySelector.MatchLabels) {
				continue
			}
		}

		matched = append(matched, result)
	}

	return matched, nil
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func (r *OsqueryAlertReconciler) evaluateCondition(alert *osqueryv1alpha1.OsqueryAlert, result *osqueryv1alpha1.QueryResult) bool {
	condition := alert.Spec.Condition

	switch condition.Type {
	case "any":
		return len(result.Spec.Rows) > 0

	case "rowCount":
		return r.evaluateRowCount(condition.RowCount, len(result.Spec.Rows))

	case "rowMatch":
		return r.evaluateRowMatch(condition.RowMatch, result.Spec.Rows)

	case "fieldThreshold":
		return r.evaluateFieldThreshold(condition.FieldThreshold, result.Spec.Rows)

	default:
		return false
	}
}

func (r *OsqueryAlertReconciler) evaluateRowCount(cond *osqueryv1alpha1.RowCountCondition, count int) bool {
	if cond == nil {
		return false
	}

	switch cond.Operator {
	case "gt":
		return count > cond.Value
	case "gte":
		return count >= cond.Value
	case "lt":
		return count < cond.Value
	case "lte":
		return count <= cond.Value
	case "eq":
		return count == cond.Value
	default:
		return false
	}
}

func (r *OsqueryAlertReconciler) evaluateRowMatch(matches []osqueryv1alpha1.FieldMatch, rows []map[string]string) bool {
	if len(matches) == 0 {
		return false
	}

	for _, row := range rows {
		allMatch := true
		for _, match := range matches {
			if !r.fieldMatches(match, row) {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true
		}
	}

	return false
}

func (r *OsqueryAlertReconciler) fieldMatches(match osqueryv1alpha1.FieldMatch, row map[string]string) bool {
	value, exists := row[match.Field]
	if !exists {
		return false
	}

	if match.Regex != "" {
		re, err := regexp.Compile(match.Regex)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}

	if match.Equals != "" {
		return value == match.Equals
	}

	if match.NotEquals != "" {
		return value != match.NotEquals
	}

	if match.Contains != "" {
		return strings.Contains(value, match.Contains)
	}

	return true
}

func (r *OsqueryAlertReconciler) evaluateFieldThreshold(cond *osqueryv1alpha1.FieldThresholdCondition, rows []map[string]string) bool {
	if cond == nil {
		return false
	}

	for _, row := range rows {
		valueStr, exists := row[cond.Field]
		if !exists {
			continue
		}

		value, err := strconv.ParseInt(valueStr, 10, 64)
		if err != nil {
			continue
		}

		var matched bool
		switch cond.Operator {
		case "gt":
			matched = value > cond.Value
		case "gte":
			matched = value >= cond.Value
		case "lt":
			matched = value < cond.Value
		case "lte":
			matched = value <= cond.Value
		case "eq":
			matched = value == cond.Value
		}

		if matched {
			return true
		}
	}

	return false
}

func (r *OsqueryAlertReconciler) isThrottled(alert *osqueryv1alpha1.OsqueryAlert, result *osqueryv1alpha1.QueryResult) bool {
	if alert.Spec.Throttle == nil {
		return false
	}

	period, err := time.ParseDuration(alert.Spec.Throttle.Period)
	if err != nil {
		period = 15 * time.Minute
	}

	maxAlerts := alert.Spec.Throttle.MaxAlerts
	if maxAlerts <= 0 {
		maxAlerts = 1
	}

	key := r.buildThrottleKey(alert, result)

	r.throttleMu.RLock()
	times, exists := r.throttleCache[key]
	r.throttleMu.RUnlock()

	if !exists {
		return false
	}

	cutoff := time.Now().Add(-period)
	recentCount := 0
	for _, t := range times {
		if t.After(cutoff) {
			recentCount++
		}
	}

	return recentCount >= maxAlerts
}

func (r *OsqueryAlertReconciler) recordThrottle(alert *osqueryv1alpha1.OsqueryAlert, result *osqueryv1alpha1.QueryResult) {
	key := r.buildThrottleKey(alert, result)

	r.throttleMu.Lock()
	defer r.throttleMu.Unlock()

	if r.throttleCache == nil {
		r.throttleCache = make(map[string][]time.Time)
	}

	r.throttleCache[key] = append(r.throttleCache[key], time.Now())

	if alert.Spec.Throttle != nil {
		period, _ := time.ParseDuration(alert.Spec.Throttle.Period)
		if period == 0 {
			period = 15 * time.Minute
		}
		cutoff := time.Now().Add(-period * 2)

		var cleaned []time.Time
		for _, t := range r.throttleCache[key] {
			if t.After(cutoff) {
				cleaned = append(cleaned, t)
			}
		}
		r.throttleCache[key] = cleaned
	}
}

func (r *OsqueryAlertReconciler) buildThrottleKey(alert *osqueryv1alpha1.OsqueryAlert, result *osqueryv1alpha1.QueryResult) string {
	key := fmt.Sprintf("%s/%s", alert.Namespace, alert.Name)

	if alert.Spec.Throttle != nil && len(alert.Spec.Throttle.GroupBy) > 0 {
		var groupValues []string
		for _, field := range alert.Spec.Throttle.GroupBy {
			var val string
			var found bool

			switch field {
			case "nodeName":
				val, found = result.Spec.NodeName, result.Spec.NodeName != ""
			case "queryName":
				val, found = result.Spec.QueryName, result.Spec.QueryName != ""
			case "packName":
				val, found = result.Spec.PackName, result.Spec.PackName != ""
			default:
				if val, found = result.Spec.Decorations[field]; !found && len(result.Spec.Rows) > 0 {
					val, found = result.Spec.Rows[0][field]
				}
			}

			if found {
				groupValues = append(groupValues, val)
			}
		}
		if len(groupValues) > 0 {
			key += ":" + strings.Join(groupValues, ",")
		}
	}

	return key
}

func (r *OsqueryAlertReconciler) fireAlert(ctx context.Context, alert *osqueryv1alpha1.OsqueryAlert, result *osqueryv1alpha1.QueryResult) error {
	logger := log.FromContext(ctx)
	logger.Info("Firing alert", "alert", alert.Name, "result", result.Name, "severity", alert.Spec.Severity)

	var errs []error

	if alert.Spec.Notify.Kubernetes != nil && alert.Spec.Notify.Kubernetes.CreateEvent {
		if err := r.sendKubernetesEvent(ctx, alert, result); err != nil {
			errs = append(errs, fmt.Errorf("kubernetes event: %w", err))
		}
	}

	if alert.Spec.Notify.Slack != nil {
		if err := r.sendSlackNotification(ctx, alert, result); err != nil {
			errs = append(errs, fmt.Errorf("slack: %w", err))
		}
	}

	if alert.Spec.Notify.Webhook != nil {
		if err := r.sendWebhookNotification(ctx, alert, result); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}

	return nil
}

func (r *OsqueryAlertReconciler) sendKubernetesEvent(_ context.Context, alert *osqueryv1alpha1.OsqueryAlert, result *osqueryv1alpha1.QueryResult) error {
	eventType := corev1.EventTypeWarning
	if alert.Spec.Notify.Kubernetes.EventType == "Normal" {
		eventType = corev1.EventTypeNormal
	}

	message := fmt.Sprintf("Alert '%s' triggered by query '%s' on node '%s'. Rows: %d, Severity: %s",
		alert.Name,
		result.Spec.QueryName,
		result.Spec.NodeName,
		len(result.Spec.Rows),
		alert.Spec.Severity,
	)

	if len(result.Spec.Rows) > 0 {
		sample, _ := json.Marshal(result.Spec.Rows[0])
		if len(sample) > 200 {
			sample = append(sample[:200], []byte("...")...)
		}
		message += fmt.Sprintf(" Sample: %s", string(sample))
	}

	r.Recorder.Event(alert, eventType, "AlertTriggered", message)
	return nil
}

func (r *OsqueryAlertReconciler) sendSlackNotification(ctx context.Context, alert *osqueryv1alpha1.OsqueryAlert, result *osqueryv1alpha1.QueryResult) error {
	secret := &corev1.Secret{}
	secretRef := alert.Spec.Notify.Slack.WebhookSecretRef
	if err := r.Get(ctx, types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: alert.Namespace,
	}, secret); err != nil {
		return fmt.Errorf("failed to get slack secret: %w", err)
	}

	webhookURL := string(secret.Data["webhook-url"])
	if webhookURL == "" {
		return fmt.Errorf("webhook-url not found in secret")
	}

	color := r.severityToColor(alert.Spec.Severity)
	payload := map[string]any{
		"attachments": []map[string]any{
			{
				"color": color,
				"title": fmt.Sprintf("Osquery Alert: %s", alert.Name),
				"text":  fmt.Sprintf("Query `%s` triggered on node `%s`", result.Spec.QueryName, result.Spec.NodeName),
				"fields": []map[string]any{
					{"title": "Severity", "value": alert.Spec.Severity, "short": true},
					{"title": "Rows", "value": fmt.Sprintf("%d", len(result.Spec.Rows)), "short": true},
					{"title": "Node", "value": result.Spec.NodeName, "short": true},
					{"title": "Query", "value": result.Spec.QueryName, "short": true},
				},
				"ts": result.Spec.Timestamp.Unix(),
			},
		},
	}

	if alert.Spec.Notify.Slack.Channel != "" {
		payload["channel"] = alert.Spec.Notify.Slack.Channel
	}
	if alert.Spec.Notify.Slack.Username != "" {
		payload["username"] = alert.Spec.Notify.Slack.Username
	}

	return r.postJSON(ctx, webhookURL, payload)
}

func (r *OsqueryAlertReconciler) sendWebhookNotification(ctx context.Context, alert *osqueryv1alpha1.OsqueryAlert, result *osqueryv1alpha1.QueryResult) error {
	webhook := alert.Spec.Notify.Webhook

	payload := map[string]any{
		"alert":     alert.Name,
		"severity":  alert.Spec.Severity,
		"query":     result.Spec.QueryName,
		"node":      result.Spec.NodeName,
		"timestamp": result.Spec.Timestamp.Format(time.RFC3339),
		"rowCount":  len(result.Spec.Rows),
		"rows":      result.Spec.Rows,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	for k, v := range webhook.Headers {
		req.Header.Set(k, v)
	}

	if webhook.SecretRef != nil {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      webhook.SecretRef.Name,
			Namespace: alert.Namespace,
		}, secret); err == nil {
			if token := secret.Data["token"]; len(token) > 0 {
				req.Header.Set("Authorization", "Bearer "+string(token))
			}
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (r *OsqueryAlertReconciler) postJSON(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("request returned status %d", resp.StatusCode)
	}

	return nil
}

func (r *OsqueryAlertReconciler) severityToColor(severity string) string {
	switch severity {
	case "critical":
		return "#dc3545" // red
	case "high":
		return "#fd7e14" // orange
	case "medium":
		return "#ffc107" // yellow
	case "low":
		return "#17a2b8" // blue
	default:
		return "#6c757d" // gray
	}
}

func (r *OsqueryAlertReconciler) markResultAlerted(ctx context.Context, result *osqueryv1alpha1.QueryResult, alertName string) error {
	result.Status.AlertsFired = append(result.Status.AlertsFired, alertName)
	return r.Status().Update(ctx, result)
}

// SetupWithManager sets up the controller with the Manager.
func (r *OsqueryAlertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&osqueryv1alpha1.OsqueryAlert{}).
		Complete(r)
}
