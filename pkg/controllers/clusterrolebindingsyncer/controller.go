package clusterrolebindingsyncer

import (
	"context"
	"strings"
	"time"

	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ClusterRoleBindingReconciler reconciles a RBAC ClusterRoleBinding object
type ClusterRoleBindingReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	RBACConverter rbacconversion.RBACTupleConverter
	Zanzibar      zanzibar.TupleStore
	TypeRelation  *zanzibar.TypeRelation
}

//+kubebuilder:rbac:groups=rebac.luxaslabs.com,resources=typerelations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rebac.luxaslabs.com,resources=typerelations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=rebac.luxaslabs.com,resources=typerelations/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the TypeRelation object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.0/pkg/reconcile
func (r *ClusterRoleBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	logger.V(3).Info("getting clusterrolebinding", "name", req.Name)

	if strings.HasPrefix(req.Name, "system:kcp") {
		logger.Info("skipping clusterrolebinding", "name", req.Name)
		return ctrl.Result{Requeue: false, RequeueAfter: 100 * time.Minute}, nil
	}

	cr := rbacv1.ClusterRoleBinding{}
	if err := r.Client.Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, err
	}

	logger.V(3).Info("got clusterrolebinding", "clusterrolebinding", cr)

	tuples, err := r.RBACConverter.ConvertClusterRoleBindingToTuples(ctx, cr)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.V(3).Info("got tuples", "tuples", tuples)

	nodeid, err := r.TypeRelation.GetID(cr)
	if err != nil {
		return ctrl.Result{}, err
	}

	clusterrolebindingnode := zanzibar.NewNode(r.TypeRelation.TypeName, nodeid)

	adds, deletes, err := zanzibar.ReconcileCompute(ctx, r.Zanzibar, clusterrolebindingnode, tuples)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.V(3).Info("got reconcile result", "adds", adds, "deletes", deletes)

	return ctrl.Result{}, r.Zanzibar.WriteTuples(ctx, adds, deletes)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterRoleBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1.ClusterRoleBinding{}).
		Complete(r)
}
