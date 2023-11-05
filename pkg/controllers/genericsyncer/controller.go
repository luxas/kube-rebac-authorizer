package genericsyncer

import (
	"context"
	"errors"

	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// GenericTupleReconciler reconciles a Kubernetes API object into a tuple
type GenericTupleReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Zanzibar     zanzibar.TupleStore
	TypeRelation *zanzibar.TypeRelation
	GVK          schema.GroupVersionKind
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the TypeRelation object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.0/pkg/reconcile
func (r *GenericTupleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("gvk", r.GVK)

	logger.Info("getting generic object", "name", req.Name)

	obj, err := r.newObject()
	if err != nil {
		return ctrl.Result{}, err
	}

	// TODO: Do we need to register a finalizer on synced objects, or how can we detect deletions?

	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("got obj", "obj", obj)

	tuples, err := zanzibar.GenerateTuplesFor(*r.TypeRelation, obj)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("got tuples", "tuples", tuples)

	nodeid, err := r.TypeRelation.GetID(obj)
	if err != nil {
		return ctrl.Result{}, err
	}

	clusterrolenode := zanzibar.NewNode(r.TypeRelation.TypeName, nodeid)

	adds, deletes, err := zanzibar.ReconcileCompute(ctx, r.Zanzibar, clusterrolenode, tuples)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("got reconcile result", "adds", adds, "deletes", deletes)

	return ctrl.Result{}, r.Zanzibar.WriteTuples(ctx, adds, deletes)
}

// SetupWithManager sets up the controller with the Manager.
func (r *GenericTupleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	obj, err := r.newObject()
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(obj).
		Complete(r)
}

func (r *GenericTupleReconciler) newObject() (client.Object, error) {
	runtimeobj, err := r.Scheme.New(r.GVK)
	if err != nil {
		return nil, err
	}
	obj, ok := runtimeobj.(client.Object)
	if !ok {
		return nil, errors.New("cannot cast object to client.Object")
	}
	return obj, nil
}
