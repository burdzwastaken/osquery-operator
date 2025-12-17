package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

// FileIntegrityPolicyReconciler reconciles FileIntegrityPolicy objects
type FileIntegrityPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=osquery.burdz.net,resources=fileintegritypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=fileintegritypolicies/status,verbs=get;update;patch

func (r *FileIntegrityPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	policy := &osqueryv1alpha1.FileIntegrityPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling FileIntegrityPolicy", "name", policy.Name, "namespace", policy.Namespace)

	agents, err := r.getDeployedAgents(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	policy.Status.PathCount = len(policy.Spec.Paths)
	policy.Status.DeployedToAgents = agents
	now := metav1.Now()
	policy.Status.LastUpdated = &now

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *FileIntegrityPolicyReconciler) getDeployedAgents(ctx context.Context, policy *osqueryv1alpha1.FileIntegrityPolicy) ([]string, error) {
	agentList := &osqueryv1alpha1.OsqueryAgentList{}
	if err := r.List(ctx, agentList); err != nil {
		return nil, err
	}

	var agents []string
	for _, agent := range agentList.Items {
		if policy.Spec.Disabled {
			continue
		}

		if len(policy.Spec.NodeSelector) > 0 && len(agent.Spec.NodeSelector) > 0 {
			if !nodeSelectorOverlaps(agent.Spec.NodeSelector, policy.Spec.NodeSelector) {
				continue
			}
		}

		agents = append(agents, agent.Name)
	}

	return agents, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FileIntegrityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&osqueryv1alpha1.FileIntegrityPolicy{}).
		Complete(r)
}
