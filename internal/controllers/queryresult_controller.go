package controllers

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

const (
	// DefaultRetentionPeriod is the default time to keep QueryResults
	DefaultRetentionPeriod = 24 * time.Hour
)

// QueryResultReconciler reconciles QueryResult objects for retention
type QueryResultReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	RetentionPeriod time.Duration
}

// +kubebuilder:rbac:groups=osquery.burdz.net,resources=queryresults,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups=osquery.burdz.net,resources=queryresults/status,verbs=get;update;patch

func (r *QueryResultReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	result := &osqueryv1alpha1.QueryResult{}
	if err := r.Get(ctx, req.NamespacedName, result); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	retention := r.getRetentionPeriod(result)
	expiresAt := result.CreationTimestamp.Add(retention)

	if result.Status.ExpiresAt == nil {
		expiresAtTime := metav1.NewTime(expiresAt)
		result.Status.ExpiresAt = &expiresAtTime
		if err := r.Status().Update(ctx, result); err != nil {
			return ctrl.Result{}, err
		}
	}

	now := time.Now()
	if now.After(expiresAt) {
		logger.Info("Deleting expired QueryResult",
			"name", result.Name,
			"namespace", result.Namespace,
			"age", now.Sub(result.CreationTimestamp.Time),
		)
		if err := r.Delete(ctx, result); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	timeUntilExpiry := expiresAt.Sub(now)
	return ctrl.Result{RequeueAfter: timeUntilExpiry}, nil
}

func (r *QueryResultReconciler) getRetentionPeriod(result *osqueryv1alpha1.QueryResult) time.Duration {
	if result.Annotations != nil {
		if retentionStr, ok := result.Annotations[AnnotationRetention]; ok {
			return ParseDurationOrDefault(retentionStr, r.getDefaultRetention())
		}
	}
	return r.getDefaultRetention()
}

func (r *QueryResultReconciler) getDefaultRetention() time.Duration {
	if r.RetentionPeriod > 0 {
		return r.RetentionPeriod
	}
	return DefaultRetentionPeriod
}

// SetupWithManager sets up the controller with the Manager.
func (r *QueryResultReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&osqueryv1alpha1.QueryResult{}).
		Complete(r)
}
