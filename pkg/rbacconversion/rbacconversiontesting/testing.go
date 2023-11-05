package rbacconversiontesting

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"testing"

	"github.com/luxas/kube-rebac-authorizer/pkg/openfga"
	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion"
	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme, serializer.EnableStrict)
	td     = &testdataget{}
)

func init() {
	util.PanicIfError(rbacv1.AddToScheme(scheme))
}

func listToMap[T metav1.Object](items []T) map[string]T {
	m := make(map[string]T, len(items))
	for i := range items {
		t := items[i]
		m[t.GetName()] = t
	}
	return m
}

func ptrlist[T any](items []T) []*T {
	newlist := make([]*T, 0, len(items))
	for i := range items {
		newlist = append(newlist, &items[i])
	}
	return newlist
}

type testdataget struct {
	mu                  sync.Mutex
	clusterRoles        map[string]*rbacv1.ClusterRole
	clusterRoleBindings map[string]*rbacv1.ClusterRoleBinding

	roles        map[string]*rbacv1.Role
	roleBindings map[string]*rbacv1.RoleBinding
}

func (td *testdataget) initClusterRoles() {
	if td.clusterRoles == nil {
		l := rbacv1.ClusterRoleList{}
		// TODO: don't panic but use t.testing
		util.PanicIfError(runtime.DecodeInto(codecs.UniversalDecoder(), util.Must(os.ReadFile("../testdata/cluster-roles.yaml")), &l))
		td.clusterRoles = listToMap(ptrlist(l.Items))
	}
}

func (td *testdataget) initClusterRoleBindings() {
	if td.clusterRoleBindings == nil {
		l := rbacv1.ClusterRoleBindingList{}
		// TODO: don't panic but use t.testing
		util.PanicIfError(runtime.DecodeInto(codecs.UniversalDecoder(), util.Must(os.ReadFile("../testdata/cluster-role-bindings.yaml")), &l))
		td.clusterRoleBindings = listToMap(ptrlist(l.Items))
	}
}

func (td *testdataget) initRoles() {
	if td.roles == nil {
		l := rbacv1.RoleList{}
		// TODO: don't panic but use t.testing
		util.PanicIfError(runtime.DecodeInto(codecs.UniversalDecoder(), util.Must(os.ReadFile("../testdata/namespaced-roles.yaml")), &l))
		td.roles = listToMap(ptrlist(l.Items))
	}
}

func (td *testdataget) initRoleBindings() {
	if td.roleBindings == nil {
		l := rbacv1.RoleBindingList{}
		// TODO: don't panic but use t.testing
		util.PanicIfError(runtime.DecodeInto(codecs.UniversalDecoder(), util.Must(os.ReadFile("../testdata/namespaced-role-bindings.yaml")), &l))
		td.roleBindings = listToMap(ptrlist(l.Items))
	}
}

func GetClusterRole(name string) rbacv1.ClusterRole {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.initClusterRoles()

	cr, ok := td.clusterRoles[name]
	if ok {
		return *cr
	}
	return rbacv1.ClusterRole{}
}

func GetClusterRoleBinding(name string) rbacv1.ClusterRoleBinding {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.initClusterRoleBindings()

	crb, ok := td.clusterRoleBindings[name]
	if ok {
		return *crb
	}
	return rbacv1.ClusterRoleBinding{}
}

func GetRole(name string) rbacv1.Role {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.initRoles()

	nr, ok := td.roles[name]
	if ok {
		return *nr
	}
	return rbacv1.Role{}
}

func GetRoleBinding(name string) rbacv1.RoleBinding {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.initRoleBindings()

	nrb, ok := td.roleBindings[name]
	if ok {
		return *nrb
	}
	return rbacv1.RoleBinding{}
}

// SetupIntegrationTest reads the common testdata, converts RBAC into tuples, connects to
// either localhost:8081, or sets up an in-memory server (depending on callClient), then
// initializes the store, and writes all the tuples. The function returned should be ran deferred
// by the caller, for outputting debug information for failed tests.
// TODO: These now require OpenFGA to be serving on localhost:8081
func SetupIntegrationTest(ctx context.Context, t *testing.T) (debug func(), openfgaimpl *openfga.TupleStoreAndChecker) {
	// always set debug to avoid panics
	debug = func() {}

	clusterRoleNames := []string{
		"cluster-admin",
		"system:kube-controller-manager",
		"admin",
		"edit",
		"view",
		"system:discovery",
		"system:basic-user",
		"system:kube-dns",
		"system:aggregate-to-view",
		"system:aggregate-to-edit",
		"system:aggregate-to-admin",
	}

	namespacedRoleNames := []string{
		"system:controller:bootstrap-signer",
		"extension-apiserver-authentication-reader",
		"system::leader-locking-kube-controller-manager",
	}

	clusterRoleBindingNames := []string{
		"cluster-admin",
		"system:basic-user",
		"system:kube-controller-manager",
		"system:kube-dns",
		"system:public-info-viewer",
		"test:user-view",
		"test:user-admin",
	}

	namespacedRoleBindingNames := []string{
		"system:controller:bootstrap-signer",
		"system::extension-apiserver-authentication-reader",
		"system::leader-locking-kube-controller-manager",
	}

	c := &rbacconversion.GenericConverter{}

	crTuples := util.FlatMap(util.Map(clusterRoleNames, GetClusterRole), func(item rbacv1.ClusterRole) []zanzibar.Tuple {
		return util.Must(c.ConvertClusterRoleToTuples(ctx, item))
	})

	crbTuples := util.FlatMap(util.Map(clusterRoleBindingNames, GetClusterRoleBinding), func(item rbacv1.ClusterRoleBinding) []zanzibar.Tuple {
		return util.Must(c.ConvertClusterRoleBindingToTuples(ctx, item))
	})

	nrTuples := util.FlatMap(util.Map(namespacedRoleNames, GetRole), func(item rbacv1.Role) []zanzibar.Tuple {
		return util.Must(c.ConvertRoleToTuples(ctx, item))
	})

	nrbTuples := util.FlatMap(util.Map(namespacedRoleBindingNames, GetRoleBinding), func(item rbacv1.RoleBinding) []zanzibar.Tuple {
		return util.Must(c.ConvertRoleBindingToTuples(ctx, item))
	})

	openfgaAddress := "localhost:8081" // default docker: docker run -p 8080:8080 -p 8081:8081 -p 3000:3000 openfga/openfga run

	// TODO: support secure connection
	cc, err := grpc.DialContext(ctx, openfgaAddress, grpc.WithTransportCredentials(insecure.NewCredentials())) // TODO: options?
	if err != nil {
		t.Errorf("grpc.DialContext() error = %v", err)

		return
	} // TODO: Else: run an in-memory server as an option as well

	storeagnosticclient := openfga.NewStoreAgnosticClient(cc)

	debug = func() {
		if t.Failed() {
			t.Logf(
				"StoreID:%s\nClusterRoles:\n%s\n---\nClusterRoleBindings:\n%s\n---\nRoles:\n%s\n---\nRoleBindings:\n%s\n---\n",
				openfgaimpl.StoreID(),
				zanzibar.PrintTuples(crTuples),
				zanzibar.PrintTuples(crbTuples),
				zanzibar.PrintTuples(nrTuples),
				zanzibar.PrintTuples(nrbTuples),
			)
		}
	}

	storeName := "default"
	createNew := true
	if createNew {
		// Generate a random store name if we want a completely new store
		// TODO: Make an util func for this
		input := make([]byte, 16)
		_, err := rand.Read(input)
		if err != nil {
			t.Error("rand.Read", err)
			return
		}
		shasum := sha256.Sum256(input)
		storeName = hex.EncodeToString(shasum[:])
	}
	am, err := storeagnosticclient.WithStore(ctx, storeName)
	if err != nil {
		t.Errorf("storeagnosticclient.WithStore() error = %v", err)
		return
	}

	openfgaimpl, err = am.WithAuthorizationSchema(ctx, rbacconversion.GetSchema())
	if err != nil {
		t.Errorf("am.WithAuthorizationSchema() error = %v", err)
		return
	}

	if createNew {
		if err := openfgaimpl.WriteTuples(ctx, crTuples, nil); err != nil {
			t.Errorf("openfgaimpl.WriteTuples(crTuples) error = %v", err)
			return
		}

		if err := openfgaimpl.WriteTuples(ctx, crbTuples, nil); err != nil {
			t.Errorf("openfgaimpl.WriteTuples(crbTuples) error = %v", err)
			return
		}

		if err := openfgaimpl.WriteTuples(ctx, nrTuples, nil); err != nil {
			t.Errorf("openfgaimpl.WriteTuples(nrTuples) error = %v", err)
			return
		}

		if err := openfgaimpl.WriteTuples(ctx, nrbTuples, nil); err != nil {
			t.Errorf("openfgaimpl.WriteTuples(nrbTuples) error = %v", err)
			return
		}
	}

	return debug, openfgaimpl
}
