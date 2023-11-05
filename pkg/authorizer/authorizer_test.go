package authorizer

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion/rbacconversiontesting"
	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func newResourceReq(verb, apiGroup, resource, subresource string) attrsFunc {
	return newNsResourceReq(verb, apiGroup, resource, subresource, "")
}

func newNsResourceReq(verb, apiGroup, resource, subresource, namespace string) attrsFunc {
	return func(usr user.Info) authorizer.AttributesRecord {
		return authorizer.AttributesRecord{
			User: &user.DefaultInfo{
				Name:   usr.GetName(),
				Groups: usr.GetGroups(),
			},
			Verb:            verb,
			APIGroup:        apiGroup,
			Resource:        resource,
			Subresource:     subresource,
			ResourceRequest: true,
			Namespace:       namespace,
		}
	}
}

type attrsFunc func(user.Info) authorizer.AttributesRecord

func (f attrsFunc) withName(name string) attrsFunc {
	return func(i user.Info) authorizer.AttributesRecord {
		attrs := f(i)
		attrs.Name = name
		return attrs
	}
}

// TODO: Make a fake gRPC server for unit tests?

func Test_authorizerImpl_Authorize(t *testing.T) {
	tests := []struct {
		name       string
		user       user.DefaultInfo
		attrsFuncs []attrsFunc
		want       authorizer.Decision
		wantReason string
		wantErr    bool
	}{
		{
			name: "system:masters can do anything",
			user: user.DefaultInfo{Name: "foo", Groups: []string{"system:masters"}},
			attrsFuncs: []attrsFunc{
				newResourceReq("get", "", "pods", ""),
				newResourceReq("deletecollection", "", "secrets", ""),
				newResourceReq("list", "someextensiongroup", "extresource", ""),
				newResourceReq("patch", "someextensiongroup", "extresource", "status"),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "baduser should not be able to access anything",
			user: user.DefaultInfo{Name: "baduser"},
			attrsFuncs: []attrsFunc{
				newResourceReq("get", "", "pods", ""),
				newResourceReq("list", "", "secrets", ""),
				newResourceReq("list", "someextensiongroup", "extresource", ""),
				newResourceReq("patch", "someextensiongroup", "extresource", "status"),
			},
			want: authorizer.DecisionNoOpinion,
		},
		{
			name: "kcm can list/watch anything, create events, and more",
			user: user.DefaultInfo{Name: "system:kube-controller-manager"},
			attrsFuncs: []attrsFunc{
				newResourceReq("get", "", "namespaces", ""),
				newResourceReq("get", "", "secrets", ""),
				newResourceReq("create", "", "secrets", ""),
				newResourceReq("update", "", "secrets", ""),
				newResourceReq("delete", "", "secrets", ""),
				newResourceReq("update", "", "serviceaccounts", ""),
				newResourceReq("create", "", "serviceaccounts", "token"),
				newResourceReq("create", "", "events", ""),
				newResourceReq("create", "events.k8s.io", "events", ""),
				newResourceReq("list", "someextensiongroup", "extresource", ""),
				newResourceReq("watch", "someextensiongroup", "extresource", "status"),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "kcm cannot get other than allowlisted resources, or change CRDs",
			user: user.DefaultInfo{Name: "system:kube-controller-manager"},
			attrsFuncs: []attrsFunc{
				newResourceReq("get", "", "pods", ""),
				newResourceReq("get", "apps", "deployments", ""),
				newResourceReq("patch", "", "serviceaccounts", "token"),
				newResourceReq("delete", "events.k8s.io", "events", ""),
				newResourceReq("delete", "coordination.k8s.io", "leases", ""),
				newResourceReq("create", "non-k8s-events", "events", ""),
				newResourceReq("get", "someextensiongroup", "extresource", ""),
				newResourceReq("update", "someextensiongroup", "extresource", ""),
				newResourceReq("patch", "someextensiongroup", "extresource", "status"),
			},
			want: authorizer.DecisionNoOpinion,
		},
		{
			name: "any authenticated user can submit a selfsubjectaccessreview",
			user: user.DefaultInfo{Name: "any", Groups: []string{"system:authenticated"}},
			attrsFuncs: []attrsFunc{
				newResourceReq("create", "authorization.k8s.io", "selfsubjectaccessreviews", ""),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "kube-dns serviceaccount can list and watch services and endpoints",
			user: user.DefaultInfo{Name: "system:serviceaccount:kube-system:kube-dns"},
			attrsFuncs: []attrsFunc{
				newResourceReq("list", "", "services", ""),
				newResourceReq("list", "", "endpoints", ""),
				newResourceReq("watch", "", "services", ""),
				newResourceReq("watch", "", "endpoints", ""),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "kube-dns serviceaccount cannot get services, endpoints or pods",
			user: user.DefaultInfo{Name: "system:serviceaccount:kube-system:kube-dns"},
			attrsFuncs: []attrsFunc{
				newResourceReq("get", "", "services", ""),
				newResourceReq("get", "", "endpoints", ""),
				newResourceReq("get", "", "pods", ""),
			},
			want: authorizer.DecisionNoOpinion,
		},
		{
			name: "a user bound to the view clusterrole can get,list,watch many resources through the aggregated system:aggregate-to-view clusterrole",
			user: user.DefaultInfo{Name: "test:user-view"},
			attrsFuncs: []attrsFunc{
				newResourceReq("get", "", "services", ""),
				newResourceReq("list", "autoscaling", "horizontalpodautoscalers", ""),
				newResourceReq("watch", "policy", "poddisruptionbudgets", "status"),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "a user bound to the view clusterrole cannot change any resources",
			user: user.DefaultInfo{Name: "test:user-view"},
			attrsFuncs: []attrsFunc{
				// negative aggregate-to-view examples
				newResourceReq("update", "", "services", ""),
				newResourceReq("delete", "autoscaling", "horizontalpodautoscalers", ""),
				newResourceReq("patch", "policy", "poddisruptionbudgets", "status"),
				// negative aggregate-to-edit examples
				// TODO: Figure out what to do with "special" verbs
				//newResourceReq("impersonate", "", "serviceaccounts", "").withName("sa-1"), // TODO: shall we be able to do keep resourcename ""?
				newResourceReq("create", "", "pods", "proxy"),
				newResourceReq("deletecollection", "apps", "deployments", ""),
			},
			want: authorizer.DecisionNoOpinion,
		},
		{
			name: "a user bound to the admin clusterrole can do anything system:aggregate-to-{view,edit,admin} allows",
			user: user.DefaultInfo{Name: "test:user-admin"},
			attrsFuncs: []attrsFunc{
				// aggregate-to-view examples
				newResourceReq("get", "", "services", ""),
				newResourceReq("list", "autoscaling", "horizontalpodautoscalers", ""),
				newResourceReq("watch", "policy", "poddisruptionbudgets", "status"),
				// aggregate-to-edit examples
				// TODO: Figure out what to do with "special" verbs
				//newResourceReq("impersonate", "", "serviceaccounts", "").withName("sa-1"),
				newResourceReq("create", "", "pods", "proxy"),
				newResourceReq("deletecollection", "apps", "deployments", ""),
				// aggregate-to-admin examples
				newResourceReq("delete", "rbac.authorization.k8s.io", "rolebindings", ""),
				newResourceReq("update", "rbac.authorization.k8s.io", "roles", ""),
				newResourceReq("create", "authorization.k8s.io", "localsubjectaccessreviews", ""),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "a user bound to the admin clusterrole cannot access cluster-wide resources",
			user: user.DefaultInfo{Name: "test:user-admin"},
			attrsFuncs: []attrsFunc{
				// negative aggregate-to-admin examples
				newResourceReq("create", "", "namespaces", ""),
				newResourceReq("update", "rbac.authorization.k8s.io", "clusterroles", ""),
				newResourceReq("create", "rbac.authorization.k8s.io", "clusterrolesbindings", ""),
			},
			want: authorizer.DecisionNoOpinion,
		},
		{ // NOTE: the serviceaccount is in kube-system, but the accessed resources in kube-public
			name: "the bootstrap signer shall be able to access events and configmaps in kube-public",
			user: user.DefaultInfo{Name: "system:serviceaccount:kube-system:bootstrap-signer"},
			attrsFuncs: []attrsFunc{
				newNsResourceReq("get", "", "configmaps", "", "kube-public"),
				newNsResourceReq("list", "", "configmaps", "", "kube-public"),
				newNsResourceReq("watch", "", "configmaps", "", "kube-public"),
				newNsResourceReq("update", "", "configmaps", "", "kube-public").withName("cluster-info"),
				newNsResourceReq("create", "", "events", "", "kube-public"),
				newNsResourceReq("patch", "", "events", "", "kube-public"),
				newNsResourceReq("update", "", "events", "", "kube-public"),
				newNsResourceReq("create", "events.k8s.io", "events", "", "kube-public"),
				newNsResourceReq("patch", "events.k8s.io", "events", "", "kube-public"),
				newNsResourceReq("update", "events.k8s.io", "events", "", "kube-public"),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "the bootstrap signer shall not access events or configmaps in other namespaces; or delete anything",
			user: user.DefaultInfo{Name: "system:serviceaccount:kube-system:bootstrap-signer"},
			attrsFuncs: []attrsFunc{
				newNsResourceReq("get", "", "configmaps", "", "default"),
				newNsResourceReq("list", "", "configmaps", "", ""),
				newNsResourceReq("watch", "", "configmaps", "", "shouldnthaveaccesshere"),
				// it can only update the cluster-info configmap in kube-public, no others
				newNsResourceReq("update", "", "configmaps", "", "kube-public").withName("non-cluster-info"),
				newNsResourceReq("update", "", "events", "", "default"),
				newNsResourceReq("update", "events.k8s.io", "events", "", ""),
				newNsResourceReq("delete", "events.k8s.io", "events", "", "kube-public"),
				newNsResourceReq("delete", "", "events", "", "kube-public"),
				newNsResourceReq("delete", "", "configmaps", "", "kube-public"),
			},
			want: authorizer.DecisionNoOpinion,
		},
		{ // TODO: scope down to only some configmaps!
			name: "system k-c-m user should be able to get,list,watch,update configmaps in kube-system",
			user: user.DefaultInfo{Name: "system:kube-controller-manager"},
			attrsFuncs: []attrsFunc{
				newNsResourceReq("get", "", "configmaps", "", "kube-system"),
				newNsResourceReq("list", "", "configmaps", "", "kube-system"),
				newNsResourceReq("watch", "", "configmaps", "", "kube-system"),
				newNsResourceReq("update", "", "configmaps", "", "kube-system").withName("kube-controller-manager"),
				// kcm-clusterrole allows getting configmaps in any namespace
				newNsResourceReq("get", "", "configmaps", "", ""),
				// kcm-clusterrole allows watching anything in any namespace
				newNsResourceReq("watch", "", "configmaps", "", "default"),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "system k-c-m user should not edit configmaps or access in other namespaces",
			user: user.DefaultInfo{Name: "system:kube-controller-manager"},
			attrsFuncs: []attrsFunc{
				newNsResourceReq("delete", "", "configmaps", "", "kube-system"),
				newNsResourceReq("update", "", "configmaps", "", "kube-public"),
			},
			want: authorizer.DecisionNoOpinion,
		},
		{
			// the difference between this and the system:kube-controller-manager user is that the
			// system:kube-controller-manager user is bound to both the
			// system::leader-locking-kube-controller-manager Role AND system:kube-controller-manager ClusterRole
			// but the ServiceAccount detailed here is only bound to the
			// system::leader-locking-kube-controller-manager Role
			name: "k-c-m serviceaccount should be able to get,watch,update configmaps in kube-system",
			user: user.DefaultInfo{Name: "system:serviceaccount:kube-system:kube-controller-manager"},
			attrsFuncs: []attrsFunc{
				newNsResourceReq("watch", "", "configmaps", "", "kube-system"),
				newNsResourceReq("get", "", "configmaps", "", "kube-system").withName("kube-controller-manager"),
				newNsResourceReq("update", "", "configmaps", "", "kube-system").withName("kube-controller-manager"),
			},
			want: authorizer.DecisionAllow,
		},
		{
			name: "k-c-m serviceaccount should not list,edit configmaps in kube-system or access in other namespaces",
			user: user.DefaultInfo{Name: "system:serviceaccount:kube-system:kube-controller-manager"},
			attrsFuncs: []attrsFunc{
				newNsResourceReq("list", "", "configmaps", "", "kube-system"),
				newNsResourceReq("delete", "", "configmaps", "", "kube-system"),
				newNsResourceReq("get", "", "configmaps", "", ""),
				newNsResourceReq("watch", "", "configmaps", "", "default"),
				newNsResourceReq("update", "", "configmaps", "", "kube-public"),
				newNsResourceReq("get", "", "configmaps", "", "kube-system").withName("not-kube-controller-manager"),
				newNsResourceReq("update", "", "configmaps", "", "kube-system").withName("not-kube-controller-manager"),
				// should not be authorized to see any configmap with the same name in any other namespace
				newNsResourceReq("update", "", "configmaps", "", "default").withName("not-kube-controller-manager"),
			},
			want: authorizer.DecisionNoOpinion,
		},
	}

	ctx := context.Background()
	// TODO: These now require OpenFGA to be serving on localhost:8081
	debug, openfgaimpl := rbacconversiontesting.SetupIntegrationTest(ctx, t)
	defer debug()

	if openfgaimpl == nil {
		return
	}

	a := &ReBACAuthorizer{
		Checker: openfgaimpl,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			for _, attrFunc := range tt.attrsFuncs {
				attrs := attrFunc(&tt.user)

				got, got1, err := a.Authorize(ctx, attrs)
				if (err != nil) != tt.wantErr {
					t.Errorf("authorizerImpl.Authorize(%s) error = %v, wantErr %v", printAttrs(attrs), err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("authorizerImpl.Authorize(%s) got = %v, want %v", printAttrs(attrs), got, tt.want)
				}
				if got1 != tt.wantReason {
					t.Errorf("authorizerImpl.Authorize(%s) got1 = %v, want %v", printAttrs(attrs), got1, tt.wantReason)
				}
			}
		})
	}
}

func printAttrs(attrs authorizer.Attributes) string {
	return string(util.Must(json.MarshalIndent(attrs, "", "  ")))
}
