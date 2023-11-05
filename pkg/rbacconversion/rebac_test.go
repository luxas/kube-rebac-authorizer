package rbacconversion_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion"
	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion/rbacconversiontesting"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
)

var printTuples = zanzibar.PrintTuples

type Tuple = zanzibar.Tuple

func Test_converter_ConvertClusterRolesToTuples(t *testing.T) {
	tests := []struct {
		name            string
		clusterRoleName string
		want            []Tuple
		wantErr         bool
	}{
		{
			name:            "cluster-admin",
			clusterRoleName: "cluster-admin",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole", "cluster-admin", "assignee", "anyverb", "resource", "*.*"),
				zanzibar.NewUserSetTuple("clusterrole", "cluster-admin", "assignee", "anyverb", "nonresourceurls", "/*"),
			},
		},
		{
			name:            "system:kube-controller-manager",
			clusterRoleName: "system:kube-controller-manager",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "create", "resource", "core.events"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "patch", "resource", "core.events"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "update", "resource", "core.events"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "create", "resource", "events.k8s.io.events"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "patch", "resource", "events.k8s.io.events"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "update", "resource", "events.k8s.io.events"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "create", "resource", "coordination.k8s.io.leases"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "get", "resourceinstance", "coordination.k8s.io.leases/kube-controller-manager"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "update", "resourceinstance", "coordination.k8s.io.leases/kube-controller-manager"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "create", "resource", "core.secrets"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "create", "resource", "core.serviceaccounts"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "delete", "resource", "core.secrets"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "get", "resource", "core.configmaps"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "get", "resource", "core.namespaces"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "get", "resource", "core.secrets"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "get", "resource", "core.serviceaccounts"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "update", "resource", "core.secrets"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "update", "resource", "core.serviceaccounts"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "create", "resource", "authentication.k8s.io.tokenreviews"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "create", "resource", "authorization.k8s.io.subjectaccessreviews"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "list", "resource", "*.*"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "watch", "resource", "*.*"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Akube-controller-manager", "assignee", "create", "resource", "core.serviceaccounts/token"),
			},
		},
		{
			name:            "aggregated admin",
			clusterRoleName: "admin",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole", "admin", "assignee", "selects", "clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-admin=true"),
			},
		},
		{
			name:            "aggregated edit",
			clusterRoleName: "edit",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-admin=true", "selects", "assignee", "clusterrole", "edit"),
				zanzibar.NewUserSetTuple("clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-admin", "selects", "assignee", "clusterrole", "edit"),
				zanzibar.NewUserSetTuple("clusterrole", "edit", "assignee", "selects", "clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-edit=true"),
			},
		},
		{
			name:            "aggregated view",
			clusterRoleName: "view",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-edit=true", "selects", "assignee", "clusterrole", "view"),
				zanzibar.NewUserSetTuple("clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-edit", "selects", "assignee", "clusterrole", "view"),
				zanzibar.NewUserSetTuple("clusterrole", "view", "assignee", "selects", "clusterrole_label", "rbac.authorization.k8s.io/aggregate-to-view=true"),
			},
		},
		{
			name:            "non-resource discovery",
			clusterRoleName: "system:discovery",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/api"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/api/*"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/apis"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/apis/*"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/healthz"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/livez"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/openapi"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/openapi/*"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/readyz"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/version"),
				zanzibar.NewUserSetTuple("clusterrole", "system%3Adiscovery", "assignee", "get", "nonresourceurls", "/version/"),
			},
		},
	}
	for _, tt := range tests {
		ctx := context.Background()
		t.Run(tt.name, func(t *testing.T) {
			gc := &rbacconversion.GenericConverter{}

			got, err := gc.ConvertClusterRoleToTuples(ctx, rbacconversiontesting.GetClusterRole(tt.clusterRoleName))
			if (err != nil) != tt.wantErr {
				t.Errorf("GenericConverter.ConvertClusterRolesToTuples() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			zanzibar.Tuples(got).AssertEqualsWanted(tt.want, t, "GenericConverter.ConvertClusterRolesToTuples")
		})
	}
}

func Test_converter_ConvertRolesToTuples(t *testing.T) {
	tests := []struct {
		name     string
		roleName string
		want     zanzibar.Tuples
		wantErr  bool
	}{
		{
			name:     "extension-apiserver-authentication-reader",
			roleName: "extension-apiserver-authentication-reader",
			want: []Tuple{
				zanzibar.NewTuple("namespace", "kube-system", "contains", "role", "kube-system/extension-apiserver-authentication-reader"),
				zanzibar.NewUserSetTuple("role", "kube-system/extension-apiserver-authentication-reader", "assignee", "get", "resourceinstance", "core.configmaps/extension-apiserver-authentication"),
				zanzibar.NewUserSetTuple("role", "kube-system/extension-apiserver-authentication-reader", "assignee", "watch", "resourceinstance", "core.configmaps/extension-apiserver-authentication"),
			},
		},
		{
			name:     "system::leader-locking-kube-controller-manager",
			roleName: "system::leader-locking-kube-controller-manager",
			want: []Tuple{
				zanzibar.NewTuple("namespace", "kube-system", "contains", "role", "kube-system/system%3A%3Aleader-locking-kube-controller-manager"),
				zanzibar.NewUserSetTuple("role", "kube-system/system%3A%3Aleader-locking-kube-controller-manager", "assignee", "watch", "resource", "core.configmaps"),
				zanzibar.NewUserSetTuple("role", "kube-system/system%3A%3Aleader-locking-kube-controller-manager", "assignee", "get", "resourceinstance", "core.configmaps/kube-controller-manager"),
				zanzibar.NewUserSetTuple("role", "kube-system/system%3A%3Aleader-locking-kube-controller-manager", "assignee", "update", "resourceinstance", "core.configmaps/kube-controller-manager"),
			},
		},
		{
			name:     "system:controller:bootstrap-signer",
			roleName: "system:controller:bootstrap-signer",
			want: []Tuple{
				zanzibar.NewTuple("namespace", "kube-public", "contains", "role", "kube-public/system%3Acontroller%3Abootstrap-signer"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "get", "resource", "core.configmaps"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "list", "resource", "core.configmaps"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "watch", "resource", "core.configmaps"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "update", "resourceinstance", "core.configmaps/cluster-info"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "create", "resource", "core.events"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "patch", "resource", "core.events"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "update", "resource", "core.events"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "create", "resource", "events.k8s.io.events"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "patch", "resource", "events.k8s.io.events"),
				zanzibar.NewUserSetTuple("role", "kube-public/system%3Acontroller%3Abootstrap-signer", "assignee", "update", "resource", "events.k8s.io.events"),
			},
		},
	}
	for _, tt := range tests {
		ctx := context.Background()
		t.Run(tt.name, func(t *testing.T) {
			gc := &rbacconversion.GenericConverter{}

			got, err := gc.ConvertRoleToTuples(ctx, rbacconversiontesting.GetRole(tt.roleName))
			if (err != nil) != tt.wantErr {
				t.Errorf("GenericConverter.ConvertRolesToTuples() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			zanzibar.Tuples(got).AssertEqualsWanted(tt.want, t, "GenericConverter.ConvertRolesToTuples")
		})
	}
}

func Test_converter_ConvertClusterRoleBindingsToTuples(t *testing.T) {
	tests := []struct {
		name                   string
		clusterRoleBindingName string
		want                   []Tuple
		wantErr                bool
	}{
		{
			name:                   "cluster-admin",
			clusterRoleBindingName: "cluster-admin",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrolebinding", "cluster-admin", "assignee", "assignee", "clusterrole", "cluster-admin"),
				zanzibar.NewUserSetTuple("group", "system%3Amasters", "members", "assignee", "clusterrolebinding", "cluster-admin"),
			},
		},
		{
			name:                   "system:basic-user",
			clusterRoleBindingName: "system:basic-user",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrolebinding", "system%3Abasic-user", "assignee", "assignee", "clusterrole", "system%3Abasic-user"),
				zanzibar.NewUserSetTuple("group", "system%3Aauthenticated", "members", "assignee", "clusterrolebinding", "system%3Abasic-user"),
			},
		},
		{
			name:                   "system:kube-controller-manager",
			clusterRoleBindingName: "system:kube-controller-manager",
			want: []Tuple{
				// TODO: For this case we cannot reconcile all tuples that has this clusterrole as target.
				// Consider the case when one subject is deleted from a (Cluster)RoleBinding. Then there should be
				// n-1, instead of n, edges from user to clusterrole
				zanzibar.NewUserSetTuple("clusterrolebinding", "system%3Akube-controller-manager", "assignee", "assignee", "clusterrole", "system%3Akube-controller-manager"),
				zanzibar.NewTuple("user", "system%3Akube-controller-manager", "assignee", "clusterrolebinding", "system%3Akube-controller-manager"),
			},
		},
		{
			name:                   "system:kube-dns",
			clusterRoleBindingName: "system:kube-dns",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrolebinding", "system%3Akube-dns", "assignee", "assignee", "clusterrole", "system%3Akube-dns"),
				zanzibar.NewTuple("user", "system%3Aserviceaccount%3Akube-system%3Akube-dns", "assignee", "clusterrolebinding", "system%3Akube-dns"),
			},
		},
		{
			name:                   "system:public-info-viewer",
			clusterRoleBindingName: "system:public-info-viewer",
			want: []Tuple{
				zanzibar.NewUserSetTuple("clusterrolebinding", "system%3Apublic-info-viewer", "assignee", "assignee", "clusterrole", "system%3Apublic-info-viewer"),
				zanzibar.NewUserSetTuple("group", "system%3Aauthenticated", "members", "assignee", "clusterrolebinding", "system%3Apublic-info-viewer"),
				zanzibar.NewUserSetTuple("group", "system%3Aunauthenticated", "members", "assignee", "clusterrolebinding", "system%3Apublic-info-viewer"),
			},
		},
	}

	for _, tt := range tests {
		ctx := context.Background()
		t.Run(tt.name, func(t *testing.T) {

			gc := &rbacconversion.GenericConverter{}
			got, err := gc.ConvertClusterRoleBindingToTuples(ctx, rbacconversiontesting.GetClusterRoleBinding(tt.clusterRoleBindingName))
			if (err != nil) != tt.wantErr {
				t.Errorf("GenericConverter.ConvertClusterRoleBindingsToTuples() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// TODO: Diff only those tuples that are not equal
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenericConverter.ConvertClusterRoleBindingsToTuples() = %v, want %v", printTuples(got), printTuples(tt.want))
			}
		})
	}
}

func Test_converter_ConvertRoleBindingsToTuples(t *testing.T) {
	tests := []struct {
		name            string
		roleBindingName string
		want            []Tuple
		wantErr         bool
	}{
		{
			name:            "system:controller:bootstrap-signer",
			roleBindingName: "system:controller:bootstrap-signer",
			want: []Tuple{
				zanzibar.NewUserSetTuple("rolebinding", "kube-public/system%3Acontroller%3Abootstrap-signer", "namespaced_assignee", "namespaced_assignee", "role", "kube-public/system%3Acontroller%3Abootstrap-signer"),
				zanzibar.NewTuple("user", "system%3Aserviceaccount%3Akube-system%3Abootstrap-signer", "namespaced_assignee", "rolebinding", "kube-public/system%3Acontroller%3Abootstrap-signer"),
			},
		},
		{
			name:            "system::extension-apiserver-authentication-reader",
			roleBindingName: "system::extension-apiserver-authentication-reader",
			want: []Tuple{
				zanzibar.NewUserSetTuple("rolebinding", "kube-system/system%3A%3Aextension-apiserver-authentication-reader", "namespaced_assignee", "namespaced_assignee", "role", "kube-system/extension-apiserver-authentication-reader"),
				zanzibar.NewTuple("user", "system%3Akube-controller-manager", "namespaced_assignee", "rolebinding", "kube-system/system%3A%3Aextension-apiserver-authentication-reader"),
				zanzibar.NewTuple("user", "system%3Akube-scheduler", "namespaced_assignee", "rolebinding", "kube-system/system%3A%3Aextension-apiserver-authentication-reader"),
			},
		},
		{
			name:            "system::leader-locking-kube-controller-manager",
			roleBindingName: "system::leader-locking-kube-controller-manager",
			want: []Tuple{
				zanzibar.NewUserSetTuple("rolebinding", "kube-system/system%3A%3Aleader-locking-kube-controller-manager", "namespaced_assignee", "namespaced_assignee", "role", "kube-system/system%3A%3Aleader-locking-kube-controller-manager"),
				zanzibar.NewTuple("user", "system%3Akube-controller-manager", "namespaced_assignee", "rolebinding", "kube-system/system%3A%3Aleader-locking-kube-controller-manager"),
				zanzibar.NewTuple("user", "system%3Aserviceaccount%3Akube-system%3Akube-controller-manager", "namespaced_assignee", "rolebinding", "kube-system/system%3A%3Aleader-locking-kube-controller-manager"),
			},
		},
	}
	for _, tt := range tests {
		ctx := context.Background()
		t.Run(tt.name, func(t *testing.T) {

			gc := &rbacconversion.GenericConverter{}

			got, err := gc.ConvertRoleBindingToTuples(ctx, rbacconversiontesting.GetRoleBinding(tt.roleBindingName))
			if (err != nil) != tt.wantErr {
				t.Errorf("GenericConverter.ConvertRoleBindingsToTuples() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// TODO: Diff only those tuples that are not equal
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenericConverter.ConvertRoleBindingsToTuples() = %v, want %v", printTuples(got), printTuples(tt.want))
			}
		})
	}
}
