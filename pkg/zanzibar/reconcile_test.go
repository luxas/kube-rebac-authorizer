package zanzibar_test

import (
	context "context"
	"reflect"
	"testing"

	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion"
	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion/rbacconversiontesting"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	"gotest.tools/v3/assert"
)

/*
type tupleRequest struct {
	objectType      string
	userSetRelation string
	response        []Tuple
}

// TODO: Maybe revive this unit test in the future. However, the integration test below
// is much better in terms of testing quality.
func TestReconcile(t *testing.T) {

	tests := []struct {
		name                  string
		existingObjectTuples  []Tuple
		existingUserTuples    tupleRequest
		existingUserSetTuples tupleRequest
		node                  zanzibar.Node
		desiredTuples         []Tuple
		wantAdded             []Tuple
		wantDeleted           []Tuple
		targetErr             error
	}{
		{
			name: "only adds",
			node: rbacconversion.ClusterRoleNode("foo"),
			desiredTuples: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrole", "foo"),
				zanzibar.NewTuple("group", "bar", "assignee", "clusterrole", "foo"),
			},
			wantAdded: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrole", "foo"),
				zanzibar.NewTuple("group", "bar", "assignee", "clusterrole", "foo"),
			},
		},
		{
			name: "only deletes",
			node: rbacconversion.ClusterRoleNode("foo"),
			existingObjectTuples: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrole", "foo"),
				zanzibar.NewTuple("group", "bar", "assignee", "clusterrole", "foo"),
			},
			wantDeleted: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrole", "foo"),
				zanzibar.NewTuple("group", "bar", "assignee", "clusterrole", "foo"),
			},
		},
		{
			name: "desired and actual equal",
			node: rbacconversion.ClusterRoleNode("foo"),
			existingObjectTuples: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrole", "foo"),
				zanzibar.NewTuple("group", "bar", "assignee", "clusterrole", "foo"),
			},
			desiredTuples: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrole", "foo"),
				zanzibar.NewTuple("group", "bar", "assignee", "clusterrole", "foo"),
			},
		},
		{
			name: "mix of incoming",
			node: rbacconversion.ClusterRoleNode("foo"),
			existingObjectTuples: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrole", "foo"),
				zanzibar.NewTuple("group", "bar", "assignee", "clusterrole", "foo"),
			},
			desiredTuples: []Tuple{
				zanzibar.NewTuple("group", "bar", "assignee", "clusterrole", "foo"),
				zanzibar.NewTuple("group", "baz", "assignee", "clusterrole", "foo"),
			},
			wantAdded: []Tuple{
				zanzibar.NewTuple("group", "baz", "assignee", "clusterrole", "foo"),
			},
			wantDeleted: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrole", "foo"),
			},
		},
	}
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := zanzibar.NewMockTupleStore(t)
			s.EXPECT().ReadTuples(ctx, zanzibar.TupleFilter{
				ObjectType: tt.node.NodeType(),
				ObjectName: tt.node.NodeName(),
			}).Return(tt.existingObjectTuples, nil)

			s.EXPECT().WriteTuples(ctx, tt.wantAdded, tt.wantDeleted).Return(nil)
			err := Reconcile(ctx, s, tt.node, tt.desiredTuples)
			assert.ErrorIs(t, err, tt.targetErr, "Reconcile")
		})
	}
}*/

type Tuple = zanzibar.Tuple

func TestReconcileIntegration(t *testing.T) {
	tests := []struct {
		name          string
		node          zanzibar.Node
		desiredTuples []Tuple
		wantAdded     []Tuple
		wantDeleted   []Tuple
		targetErr     error
	}{
		{
			name: "no-op",
			node: rbacconversion.ClusterRoleNode("admin"),
			desiredTuples: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole", "admin", "assignee", "selects", "clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-admin=true"),
			},
		},
		{
			name:          "delete all",
			node:          rbacconversion.ClusterRoleNode("admin"),
			desiredTuples: []Tuple{},
			wantDeleted: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole", "admin", "assignee", "selects", "clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-admin=true"),
			},
		},
		{
			name: "add new clusterrole",
			node: rbacconversion.ClusterRoleNode("newclusterrole"),
			desiredTuples: []Tuple{
				// TODO: If we try adding things that are not compliant with the "rules", should we apply or ignore those?
				zanzibar.NewUserSetTuple("clusterrole", "newclusterrole", "assignee", "create", "resource", "core.events"),
				zanzibar.NewUserSetTuple("clusterrolebinding", "newclusterrole", "assignee", "assignee", "clusterrole", "newclusterrole"),
			},
			wantAdded: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole", "newclusterrole", "assignee", "create", "resource", "core.events"),
				zanzibar.NewUserSetTuple("clusterrolebinding", "newclusterrole", "assignee", "assignee", "clusterrole", "newclusterrole"),
			},
		},
		{
			name: "add one, delete one",
			node: rbacconversion.ClusterRoleBindingNode("system:public-info-viewer"),
			desiredTuples: []Tuple{
				zanzibar.NewUserSetTuple("clusterrolebinding", "system%3Apublic-info-viewer", "assignee", "assignee", "clusterrole", "system%3Apublic-info-viewer"),
				zanzibar.NewUserSetTuple("group", "system%3Aauthenticated", "members", "assignee", "clusterrolebinding", "system%3Apublic-info-viewer"),
				// deleted
				//zanzibar.NewUserSetTuple("group", "system%3Aunauthenticated", "members", "assignee", "clusterrolebinding", "system%3Apublic-info-viewer"),
				// added
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrolebinding", "system%3Apublic-info-viewer"),
			},
			wantAdded: []Tuple{
				zanzibar.NewTuple("user", "foo", "assignee", "clusterrolebinding", "system%3Apublic-info-viewer"),
			},
			wantDeleted: []Tuple{
				zanzibar.NewUserSetTuple("group", "system%3Aunauthenticated", "members", "assignee", "clusterrolebinding", "system%3Apublic-info-viewer"),
			},
		},
	}
	ctx := context.Background()
	debug, openfgaimpl := rbacconversiontesting.SetupIntegrationTest(ctx, t)
	defer debug()

	if openfgaimpl == nil {
		return
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adds, deletes, err := zanzibar.ReconcileCompute(ctx, openfgaimpl, tt.node, tt.desiredTuples)
			if !reflect.DeepEqual(adds, tt.wantAdded) {
				t.Errorf("openfga.ReconcileCompute(added) = %v, want %v",
					zanzibar.PrintTuples(adds), zanzibar.PrintTuples(tt.wantAdded))
			}
			// TODO: Move this DeepEqual into testing utils.
			if !reflect.DeepEqual(deletes, tt.wantDeleted) {
				t.Errorf("openfga.ReconcileCompute(deleted) = %v, want %v",
					zanzibar.PrintTuples(deletes), zanzibar.PrintTuples(tt.wantDeleted))
			}
			assert.ErrorIs(t, err, tt.targetErr, "Reconcile")
		})
	}
}
