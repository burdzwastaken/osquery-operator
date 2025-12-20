package controllers

import (
	"context"
	"encoding/json"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

// DistributedQueryReconciler reconciles DistributedQuery resources.
// It dispatches ad-hoc queries to targeted nodes via ConfigMaps and
// collects results from QueryResult CRs created by the k8s-event-bridge.
type DistributedQueryReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=osquery.burdz.net,resources=distributedqueries,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=distributedqueries/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=distributedqueries/finalizers,verbs=update
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=queryresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods/exec,verbs=create

// Reconcile handles DistributedQuery lifecycle: dispatches queries to nodes,
// monitors for results, handles timeouts, and cleans up after TTL expiry.
func (r *DistributedQueryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	dq := &osqueryv1alpha1.DistributedQuery{}
	if err := r.Get(ctx, req.NamespacedName, dq); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling DistributedQuery", "name", dq.Name, "phase", dq.Status.Phase)

	if shouldDelete, err := r.handleTTL(ctx, dq); err != nil {
		return ctrl.Result{}, err
	} else if shouldDelete {
		return ctrl.Result{}, r.Delete(ctx, dq)
	}

	switch dq.Status.Phase {
	case "", PhasePending:
		return r.handlePending(ctx, dq)
	case PhaseRunning:
		return r.handleRunning(ctx, dq)
	case PhaseCompleted, PhaseFailed, PhaseTimedOut:
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *DistributedQueryReconciler) handleTTL(_ context.Context, dq *osqueryv1alpha1.DistributedQuery) (bool, error) {
	if dq.Status.Phase != PhaseCompleted && dq.Status.Phase != PhaseFailed && dq.Status.Phase != PhaseTimedOut {
		return false, nil
	}

	if dq.Status.CompletionTime == nil {
		return false, nil
	}

	ttl := ParseDurationOrDefault(dq.Spec.TTL, time.Hour)
	expiresAt := dq.Status.CompletionTime.Add(ttl)
	return time.Now().After(expiresAt), nil
}

func (r *DistributedQueryReconciler) handlePending(ctx context.Context, dq *osqueryv1alpha1.DistributedQuery) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	targetNodes, err := r.getTargetNodes(ctx, dq)
	if err != nil {
		return ctrl.Result{}, err
	}

	if len(targetNodes) == 0 {
		dq.Status.Phase = PhaseFailed
		dq.Status.Conditions = append(dq.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "NoTargetNodes",
			Message:            "No nodes match the node selector",
			LastTransitionTime: metav1.Now(),
		})
		return ctrl.Result{}, r.Status().Update(ctx, dq)
	}

	logger.Info("Dispatching distributed query", "targetNodes", len(targetNodes))

	if err := r.createQueryConfigMap(ctx, dq, targetNodes); err != nil {
		return ctrl.Result{}, err
	}

	now := metav1.Now()
	dq.Status.Phase = PhaseRunning
	dq.Status.TargetNodes = len(targetNodes)
	dq.Status.StartTime = &now
	dq.Status.NodeResults = make([]osqueryv1alpha1.NodeQueryResult, len(targetNodes))

	for i, node := range targetNodes {
		dq.Status.NodeResults[i] = osqueryv1alpha1.NodeQueryResult{
			NodeName: node,
			Status:   PhasePending,
		}
	}

	return ctrl.Result{RequeueAfter: 5 * time.Second}, r.Status().Update(ctx, dq)
}

func (r *DistributedQueryReconciler) handleRunning(ctx context.Context, dq *osqueryv1alpha1.DistributedQuery) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	timeout := ParseDurationOrDefault(dq.Spec.Timeout, 60*time.Second)

	if dq.Status.StartTime != nil && time.Since(dq.Status.StartTime.Time) > timeout {
		logger.Info("Distributed query timed out")
		dq.Status.Phase = PhaseTimedOut
		now := metav1.Now()
		dq.Status.CompletionTime = &now

		for i := range dq.Status.NodeResults {
			if dq.Status.NodeResults[i].Status == PhasePending {
				dq.Status.NodeResults[i].Status = PhaseTimedOut
				dq.Status.FailedNodes++
			}
		}

		return ctrl.Result{}, r.Status().Update(ctx, dq)
	}

	updated := false
	for i, nodeResult := range dq.Status.NodeResults {
		if nodeResult.Status != PhasePending {
			continue
		}

		result, err := r.checkNodeResult(ctx, dq, nodeResult.NodeName)
		if err != nil {
			logger.Error(err, "Error checking node result", "node", nodeResult.NodeName)
			dq.Status.NodeResults[i].Status = PhaseFailed
			dq.Status.NodeResults[i].Error = err.Error()
			dq.Status.FailedNodes++
			updated = true
			continue
		}

		if result != nil {
			dq.Status.NodeResults[i].Status = PhaseCompleted
			dq.Status.NodeResults[i].RowCount = len(result.Spec.Rows)
			dq.Status.NodeResults[i].Rows = result.Spec.Rows
			now := metav1.Now()
			dq.Status.NodeResults[i].CompletedAt = &now
			dq.Status.CompletedNodes++
			dq.Status.TotalRows += len(result.Spec.Rows)
			updated = true
		}
	}

	if dq.Status.CompletedNodes+dq.Status.FailedNodes >= dq.Status.TargetNodes {
		if dq.Status.FailedNodes > 0 {
			dq.Status.Phase = PhaseFailed
		} else {
			dq.Status.Phase = PhaseCompleted
		}
		now := metav1.Now()
		dq.Status.CompletionTime = &now
		updated = true
	}

	if updated {
		if err := r.Status().Update(ctx, dq); err != nil {
			return ctrl.Result{}, err
		}
	}

	if dq.Status.Phase == PhaseRunning {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

func (r *DistributedQueryReconciler) getTargetNodes(ctx context.Context, dq *osqueryv1alpha1.DistributedQuery) ([]string, error) {
	nodeList := &corev1.NodeList{}
	if err := r.List(ctx, nodeList); err != nil {
		return nil, err
	}

	var targetNodes []string
	for _, node := range nodeList.Items {
		if LabelsMatch(node.Labels, dq.Spec.NodeSelector) {
			targetNodes = append(targetNodes, node.Name)
		}
	}

	return targetNodes, nil
}

func (r *DistributedQueryReconciler) createQueryConfigMap(ctx context.Context, dq *osqueryv1alpha1.DistributedQuery, targetNodes []string) error {
	queryData := map[string]any{
		"query":        dq.Spec.Query,
		"cardinality":  dq.Spec.Cardinality,
		"target_nodes": targetNodes,
		"query_id":     string(dq.UID),
	}

	queryJSON, err := json.Marshal(queryData)
	if err != nil {
		return err
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dq-" + dq.Name,
			Namespace: dq.Namespace,
			Labels: map[string]string{
				AnnotationDistributedQuery: dq.Name,
			},
		},
		Data: map[string]string{
			"query.json": string(queryJSON),
		},
	}

	if err := ctrl.SetControllerReference(dq, cm, r.Scheme); err != nil {
		return err
	}

	return r.Create(ctx, cm)
}

func (r *DistributedQueryReconciler) checkNodeResult(ctx context.Context, dq *osqueryv1alpha1.DistributedQuery, nodeName string) (*osqueryv1alpha1.QueryResult, error) {
	resultList := &osqueryv1alpha1.QueryResultList{}
	if err := r.List(ctx, resultList, client.InNamespace(dq.Namespace)); err != nil {
		return nil, err
	}

	for _, result := range resultList.Items {
		if result.Spec.DistributedQueryRef == dq.Name && result.Spec.NodeName == nodeName {
			return &result, nil
		}
	}

	return nil, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *DistributedQueryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&osqueryv1alpha1.DistributedQuery{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}
