package controllers

import (
	"context"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

const complianceRequeueInterval = 5 * time.Minute

const (
	LabelCompliancePolicy  = "osquery.burdz.net/compliance-policy"
	LabelComplianceManaged = "osquery.burdz.net/compliance-managed"
	LabelPack              = "osquery.burdz.net/pack"
)

type CompliancePolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=osquery.burdz.net,resources=compliancepolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=compliancepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=compliancepolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=osquerypacks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=queryresults,verbs=get;list;watch

func (r *CompliancePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	policy := &osqueryv1alpha1.CompliancePolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling CompliancePolicy", "name", policy.Name)

	if policy.Spec.Disabled {
		if err := r.deleteGeneratedPack(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
		return r.updateStatus(ctx, policy, "", nil)
	}

	packName, err := r.reconcileOsqueryPack(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	queryResults, err := r.getQueryResults(ctx, packName)
	if err != nil {
		logger.Error(err, "Failed to get QueryResults")
		return r.updateStatus(ctx, policy, packName, nil)
	}

	controlResults := r.evaluateControls(policy, queryResults)

	return r.updateStatus(ctx, policy, packName, controlResults)
}

func (r *CompliancePolicyReconciler) getQueryResults(ctx context.Context, packName string) (*osqueryv1alpha1.QueryResultList, error) {
	results := &osqueryv1alpha1.QueryResultList{}
	if err := r.List(ctx, results, client.MatchingLabels{LabelPack: sanitizeLabelValue(packName)}); err != nil {
		return nil, err
	}
	return results, nil
}

func (r *CompliancePolicyReconciler) evaluateControls(policy *osqueryv1alpha1.CompliancePolicy, results *osqueryv1alpha1.QueryResultList) []osqueryv1alpha1.ControlResult {
	controlResults := make([]osqueryv1alpha1.ControlResult, 0, len(policy.Spec.Controls))

	resultsByQuery := make(map[string][]osqueryv1alpha1.QueryResult)
	if results != nil {
		for _, qr := range results.Items {
			resultsByQuery[qr.Spec.QueryName] = append(resultsByQuery[qr.Spec.QueryName], qr)
		}
	}

	for _, control := range policy.Spec.Controls {
		if control.Disabled {
			continue
		}

		queryName := sanitizeQueryName(control.ID + "-" + control.Title)
		queryResults := resultsByQuery[queryName]

		cr := r.evaluateControl(control, queryResults)
		controlResults = append(controlResults, cr)
	}

	return controlResults
}

func (r *CompliancePolicyReconciler) evaluateControl(control osqueryv1alpha1.ComplianceControl, results []osqueryv1alpha1.QueryResult) osqueryv1alpha1.ControlResult {
	cr := osqueryv1alpha1.ControlResult{
		ID:     control.ID,
		Status: "unknown",
	}

	if len(results) == 0 {
		cr.Message = "No query results available"
		return cr
	}

	totalRows := 0
	affectedNodes := make(map[string]bool)
	var latestTime *metav1.Time

	for i := range results {
		qr := &results[i]
		rowCount := len(qr.Spec.Rows)
		totalRows += rowCount

		if rowCount > 0 {
			affectedNodes[qr.Spec.NodeName] = true
		}

		if latestTime == nil || qr.Spec.Timestamp.After(latestTime.Time) {
			latestTime = &qr.Spec.Timestamp
		}
	}

	cr.RowCount = &totalRows
	cr.LastChecked = latestTime

	for node := range affectedNodes {
		cr.AffectedNodes = append(cr.AffectedNodes, node)
	}

	pass := r.evaluateExpectation(control.Expectation, totalRows)
	if pass {
		cr.Status = "passing"
	} else {
		cr.Status = "failing"
	}

	return cr
}

func (r *CompliancePolicyReconciler) evaluateExpectation(expectation *osqueryv1alpha1.ControlExpectation, rowCount int) bool {
	if expectation == nil {
		return rowCount == 0
	}

	expType := expectation.Type
	if expType == "" {
		expType = "rowCount"
	}

	if expType != "rowCount" {
		return rowCount == 0
	}

	operator := expectation.Operator
	if operator == "" {
		operator = "equals"
	}

	switch operator {
	case "equals":
		return rowCount == expectation.Value
	case "lessThan":
		return rowCount < expectation.Value
	case "greaterThan":
		return rowCount > expectation.Value
	case "lessThanOrEqual":
		return rowCount <= expectation.Value
	case "greaterThanOrEqual":
		return rowCount >= expectation.Value
	default:
		return rowCount == 0
	}
}

func (r *CompliancePolicyReconciler) reconcileOsqueryPack(ctx context.Context, policy *osqueryv1alpha1.CompliancePolicy) (string, error) {
	pack := r.buildOsqueryPack(policy)

	found := &osqueryv1alpha1.OsqueryPack{}
	err := r.Get(ctx, types.NamespacedName{Name: pack.Name, Namespace: pack.Namespace}, found)

	switch {
	case errors.IsNotFound(err):
		if err := controllerutil.SetOwnerReference(policy, pack, r.Scheme); err != nil {
			return "", err
		}
		if err := r.Create(ctx, pack); err != nil {
			return "", err
		}
		return pack.Name, nil

	case err != nil:
		return "", err

	default:
		found.Spec = pack.Spec
		found.Labels = pack.Labels
		if err := r.Update(ctx, found); err != nil {
			return "", err
		}
		return found.Name, nil
	}
}

func (r *CompliancePolicyReconciler) buildOsqueryPack(policy *osqueryv1alpha1.CompliancePolicy) *osqueryv1alpha1.OsqueryPack {
	packName := "compliance-" + policy.Name

	queries := make([]osqueryv1alpha1.PackQuery, 0, len(policy.Spec.Controls))
	for _, control := range policy.Spec.Controls {
		if control.Disabled {
			continue
		}

		queryName := sanitizeQueryName(control.ID + "-" + control.Title)
		interval := control.Interval
		if interval == 0 {
			interval = 3600
		}

		severity := control.Severity
		if severity == "" {
			severity = "medium"
		}

		description := control.Description
		if description == "" {
			description = control.Title
		}
		if control.Remediation != "" {
			description = description + " | Remediation: " + control.Remediation
		}

		queries = append(queries, osqueryv1alpha1.PackQuery{
			Name:        queryName,
			Query:       control.Query,
			Interval:    interval,
			Snapshot:    true,
			Description: description,
			Severity:    severity,
		})
	}

	return &osqueryv1alpha1.OsqueryPack{
		ObjectMeta: metav1.ObjectMeta{
			Name:      packName,
			Namespace: "osquery-system",
			Labels: map[string]string{
				LabelName:                   LabelValueName,
				LabelManagedBy:              LabelValueManagedBy,
				LabelCompliancePolicy:       policy.Name,
				LabelComplianceManaged:      "true",
				"osquery.burdz.net/enabled": "true",
			},
		},
		Spec: osqueryv1alpha1.OsqueryPackSpec{
			NodeSelector: policy.Spec.NodeSelector,
			Platform:     policy.Spec.Platform,
			Queries:      queries,
		},
	}
}

func sanitizeQueryName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, "-", "_")

	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		}
	}

	sanitized := result.String()
	for strings.Contains(sanitized, "__") {
		sanitized = strings.ReplaceAll(sanitized, "__", "_")
	}
	sanitized = strings.Trim(sanitized, "_")

	if len(sanitized) > 64 {
		sanitized = sanitized[:64]
	}

	return sanitized
}

func sanitizeLabelValue(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")

	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		}
	}

	sanitized := result.String()
	sanitized = strings.Trim(sanitized, "-")

	if len(sanitized) > 63 {
		sanitized = sanitized[:63]
	}

	return sanitized
}

func (r *CompliancePolicyReconciler) deleteGeneratedPack(ctx context.Context, policy *osqueryv1alpha1.CompliancePolicy) error {
	packName := "compliance-" + policy.Name
	pack := &osqueryv1alpha1.OsqueryPack{}

	err := r.Get(ctx, types.NamespacedName{Name: packName, Namespace: "osquery-system"}, pack)
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	if pack.Labels[LabelCompliancePolicy] != policy.Name {
		return nil
	}

	return r.Delete(ctx, pack)
}

func (r *CompliancePolicyReconciler) updateStatus(ctx context.Context, policy *osqueryv1alpha1.CompliancePolicy, packName string, controlResults []osqueryv1alpha1.ControlResult) (ctrl.Result, error) {
	activeControls := 0
	for _, control := range policy.Spec.Controls {
		if !control.Disabled {
			activeControls++
		}
	}

	policy.Status.GeneratedPackName = packName
	policy.Status.TotalControls = activeControls
	policy.Status.ControlResults = controlResults

	passing := 0
	failing := 0
	unknown := 0

	for _, cr := range controlResults {
		switch cr.Status {
		case "passing":
			passing++
		case "failing":
			failing++
		default:
			unknown++
		}
	}

	policy.Status.PassingControls = passing
	policy.Status.FailingControls = failing
	policy.Status.UnknownControls = unknown

	if activeControls > 0 && len(controlResults) > 0 {
		score := (passing * 100) / activeControls
		policy.Status.Score = &score

		now := metav1.Now()
		policy.Status.LastScanTime = &now
	}

	now := metav1.Now()
	policy.Status.LastUpdated = &now

	if policy.Spec.Disabled {
		policy.Status.GeneratedPackName = ""
		policy.Status.Score = nil
		policy.Status.ControlResults = nil
	}

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: complianceRequeueInterval}, nil
}

func (r *CompliancePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&osqueryv1alpha1.CompliancePolicy{}).
		Owns(&osqueryv1alpha1.OsqueryPack{}).
		Watches(
			&osqueryv1alpha1.QueryResult{},
			handler.EnqueueRequestsFromMapFunc(r.findCompliancePolicyForQueryResult),
		).
		Complete(r)
}

func (r *CompliancePolicyReconciler) findCompliancePolicyForQueryResult(ctx context.Context, obj client.Object) []reconcile.Request {
	qr, ok := obj.(*osqueryv1alpha1.QueryResult)
	if !ok {
		return nil
	}

	packName := qr.Labels[LabelPack]
	if packName == "" || !strings.HasPrefix(packName, "compliance-") {
		return nil
	}

	policyName := strings.TrimPrefix(packName, "compliance-")

	return []reconcile.Request{
		{NamespacedName: types.NamespacedName{Name: policyName}},
	}
}
