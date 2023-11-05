package rbacconversion

import (
	"context"
	"net/url"
	"strings"

	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

/*
	Design tradeoffs:
	- We cannot support all verbs, only the common "de-facto ones"
	- We don't (by design) allow negative label selectors (such as label not exists, or label does not have value in set), as that is a very wide-open policy
	- We cannot (at least for now) support more than one label selector
*/

/*
	Kubernetes feedback:
	- RBAC names should be more restricted, like DNS subdomain + ":", not wide-open paths
	- NonResourceURLs should be validated to at least be real paths? Now there is no validation at all.
	- Can we also be more precis with NonResourceURLs, how are they written/folded/wildcarded?
	- Validate resources to conform with 1035 like CRDs, and optionally a / for subpaths.
	- How are duplicates in e.g. resources handled?
	- Verbs are not either validated?
	- Why does there exist an "approve" verb? Why not create csr/approve? Seems so the "sign" and "attest" verbs too are used in the PKI management admission controllers. One should verify this works with an API server
		only configured with webhook authz to our custom one. Its also used for GC collection (finalizers), and can be used for CEL generic admission controllers.
*/

/*
	Investigations:
	- Is it possible to form a "nonResourceURL" like /api/v1/pods? No it is not
	- curl -sSLk https://127.0.0.1:46415/apis/apps/v1/statefulset/../.. is the same as curl -sSLk https://127.0.0.1:46415/apis/apps
	- Resources are somewhere indeed validated, when the kubectl create clusterrole says that resource=foo cannot be found. It seems like apiGroup is not validated though. Or it seems to be kubectl that does this validation.
	- RBAC authorizer returns reason for allowed requests, can it be seen from anywhere?
	- Could OpenFGA add comments to the spec?
	-
*/

/*
	TODO:
	- Handle system:masters being a super-privileged group?
	- to change the aggregation rule, since it can gather anything and prevent tightening, requires * on *.* (registry/rbac/clusterrole/policybased/storage.go)
	- Handle privilege escalation; or is that left to the Storage?
	- Idea: Disable in-binary RBAC, and add an aggregated API server implementing RBAC, and more, using ONLY OpenFGA as a storage?
*/

/*
	What type produces what?
	- ClusterRole: produces
*/

// Tuple is so often used in this package we make a shorthand for it
type Tuple = zanzibar.Tuple

// TODO: With or without pointers?
type RBACTupleConverter interface {
	// ConvertClusterRoleToTuples produces Tuples related to the given ClusterRole. The tuples are produced
	// as following:
	// - One incoming Tuple from clusterrole_label#selected through the assignee relation per label
	// - One outgoing Tuple from clusterrole#assignee to the clusterrole_label type through the selected relation
	// - Per Resource Rule OR
	//    - len(apiGroups)*len(verbs)*len(resources) outgoing tuples from clusterrole#assignee to resource type
	//      through the relation related to the verb, OR
	//    - len(apiGroups)*len(verbs)*len(resources)*len(resourceNames) outgoing tuples from clusterrole#assignee
	//      to the resourceinstance type through the relation related to the verb
	// - Per Non-resource Rule:
	//    - len(nonResourceURLs)*len(verbs) outgoing tuples from clusterrole#assignee to the nonresourceurls type
	//      through the relation related to the verb
	ConvertClusterRoleToTuples(ctx context.Context, clusterrole rbacv1.ClusterRole) ([]Tuple, error)

	// ConvertRoleToTuples produces Tuples related to the given ClusterRole. The tuples are produced
	// as following:
	// - One incoming Tuple from clusterrole_label#selected through the assignee relation per label
	// - One outgoing Tuple from clusterrole#assignee to the clusterrole_label type through the selected relation
	// - Per Resource Rule OR
	//    - len(apiGroups)*len(verbs)*len(resources) outgoing tuples from clusterrole#assignee to resource type
	//      through the relation related to the verb, OR
	//    - len(apiGroups)*len(verbs)*len(resources)*len(resourceNames) outgoing tuples from clusterrole#assignee
	//      to the resourceinstance type through the relation related to the verb
	// - Per Non-resource Rule:
	//    - len(nonResourceURLs)*len(verbs) outgoing tuples from clusterrole#assignee to the nonresourceurls type
	//      through the relation related to the verb
	// TODO: Finish this documentation for all methods
	ConvertRoleToTuples(ctx context.Context, role rbacv1.Role) ([]Tuple, error)

	// RolesBinding
	ConvertClusterRoleBindingToTuples(ctx context.Context, clusterrolebinding rbacv1.ClusterRoleBinding) ([]Tuple, error)
	ConvertRoleBindingToTuples(ctx context.Context, rolebinding rbacv1.RoleBinding) ([]Tuple, error)
}

/*
	Kubernetes allows ":" in RBAC names, and only enforces it to be a valid path segment, meaning it cannot be "." or "..", and cannot contain "/" or "%".
	Otherwise, unlike other Kubernetes names needing to be a DNS1123 label, RBAC names can include for example ".", ":", "$", "#", whitespace (!) and ".." or similar.
	Source code can be found in k8s.io/kubernetes/pkg/apis/rbac/validation.ValidateRBACName
	These "name validation varies per API" things can become complicated down the road when dealing with arbitrary types.

	$ kubectl create deployment foo:bar --image nginx
	error: failed to create deployment: Deployment.apps "foo:bar" is invalid: [
		metadata.name: Invalid value: "foo:bar": a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*'),
		metadata.labels: Invalid value: "foo:bar": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?'),
		spec.selector.matchLabels: Invalid value: "foo:bar": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?'),
		spec.selector: Invalid value: v1.LabelSelector{MatchLabels:map[string]string{"app":"foo:bar"}, MatchExpressions:[]v1.LabelSelectorRequirement(nil)}: invalid label selector
	]
	$ kubectl create clusterrole foo:bar --verb=get --resource=pods
	clusterrole.rbac.authorization.k8s.io/foo:bar created

	OpenFGA disallows ":", "#" and whitespace characters in instance names, and in addition "@" for relation names.
*/

func TypedNode(typeName, instanceName string) zanzibar.Node {
	return zanzibar.NewNode(typeName, instanceName)
}

// EscapedNode escapes the instance name for resources with sloppy specifications; like RBAC names
func EscapedNode(typeName, instanceName string) zanzibar.Node {
	return TypedNode(typeName, url.QueryEscape(instanceName))
}

func ClusterRoleNode(clusterRoleName string) zanzibar.Node {
	return EscapedNode(TypeClusterRole, clusterRoleName)
}

func ClusterRoleBindingNode(clusterRoleBindingName string) zanzibar.Node {
	return EscapedNode(TypeClusterRoleBinding, clusterRoleBindingName)
}

// NamespacedRoleNode returns the zanzibar node for a namespaced role.
// As it is namespaced, it is fully qualified only with a given namespace.
// Only the role name is escaped in openfga, the namespace is known to be ok.
func NamespacedRoleNode(namespaceName, roleName string) zanzibar.Node {
	return TypedNode(TypeNamespacedRole, namespaceName+"/"+url.QueryEscape(roleName))
}

func NamespacedRoleBindingNode(namespaceName, roleBindingName string) zanzibar.Node {
	return TypedNode(TypeNamespacedRoleBinding, namespaceName+"/"+url.QueryEscape(roleBindingName))
}

// TODO: I'm pretty sure namespaces only can have sensible DNS1123 label conformant names and thus don't need escaping
func NamespaceNode(namespace string) zanzibar.Node {
	return TypedNode(TypeNamespace, namespace)
}

// ResourceNode returns the node for resource requests, such as "resource:core.pods", to which a user can have e.g. a get relation to.
// "resource:*.pods", "resource:apps.*" and "resource:*.*" are also possible. No query escaping takes place here.
func ResourceNode(apiGroup, resource string) zanzibar.Node {
	// We know that CRDs' group names always are non-empty, and are formed like a DNS 1123 subdomain with at least one dot. Thus we can treat the
	// "" group as "core" in this implementation.
	// Ref: https://github.com/kubernetes/kubernetes/blob/afc302c2d24fea7be7d6af33c79fdb81e1a33131/staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation/validation.go#L291-L297
	if apiGroup == "" {
		apiGroup = APIGroupKubernetesCore
	}

	// apiGroup is a DNS 1123 subdomain, so it can have dots (we know it has at least one, for CRDs, or is a core k8s group), but is otherwise a
	// DNS1123 label consisting only of lowercase a-z, 0-9 and dashes (not as prefix or suffix), so it fully conforms to OpenFGA's requirements
	// without escaping.

	// resource in turn is known to be a DNS 1035 label, i.e. consist of only lowercase a-z, 0-9 (not as prefix) and dashes (not as prefix or suffix),
	// so it fully conforms to OpenFGA's requirements without escaping. DNS1035 is essentially the same as DNS1123, but without allowing numbers as prefix.
	// Actually, resource can be anything UGHUGHUGH, as RBAC does not validate this either. TODO: Validate this more strictly than RBAC.
	return TypedNode(TypeResource, apiGroup+"."+resource)
}

// TODO: verify that query escaping here is ok
// TODO: need namespace here too
func ResourceInstanceNode(apiGroup, resource, instanceName string) zanzibar.Node {
	if apiGroup == "" {
		apiGroup = APIGroupKubernetesCore
	}

	// TODO: don't use this poor formatting
	return TypedNode(TypeResourceInstance, apiGroup+"."+resource+"/"+url.QueryEscape(instanceName))
}

// NonResourceNode escapes the tuple name, as the path is not validated in Kubernetes and can be anything, including have whitespace and ":"
// TODO: Validate this properly, and don't escape.
// In OpenFGA, a "/" prefix is always enforced, thus "*" in Kubernetes maps to "/*" in OpenFGA.
func NonResourceNode(nonResourceURL string) zanzibar.Node {
	// Enforce all matches to start with "/"
	if !strings.HasPrefix(nonResourceURL, "/") {
		nonResourceURL = "/" + nonResourceURL
	}
	/*if nonResourceURL == RBACMatchAllNonResources {
		nonResourceURL = ZanzibarMatchAllNonResources
	}*/

	return TypedNode(TypeNonResource, nonResourceURL)
}

// UserNode returns the node name for a user node
// TODO: Do we really have to escape this? Are there any guarantees for user names? Probably not
func UserNode(username string) zanzibar.Node {
	return TypedNode(TypeUser, url.QueryEscape(username))
}

// GroupNode returns the node name for a group node
// TODO: Do we really have to escape this? Are there any guarantees for group names? Probably not
func GroupNode(groupname string) zanzibar.Node {
	return TypedNode(TypeGroup, url.QueryEscape(groupname))
}

func ClusterRoleLabelAggregationKeyNode(key string) zanzibar.Node {
	return TypedNode(TypeClusterRoleLabelAggregation, key)
}

func ClusterRoleLabelAggregationKeyValueNode(key, value string) zanzibar.Node {
	// We can "safely" do this because the key and value are validated to be a string with characters, numbers or "_", "-", or "." (the key can have an optional "/" separator, too)
	// See k8s.io/apimachinery/pkg/util/validation.IsQualifiedName and IsValidLabelValue. OpenFGA should allow all of these values just fine, as there are no ":", "#" or whitespace.
	return TypedNode(TypeClusterRoleLabelAggregation, key+"="+value)
}

func ClusterRoleLabelAggregationNodes(key, value string) zanzibar.Nodes {
	return zanzibar.NewNodes(
		ClusterRoleLabelAggregationKeyValueNode(key, value),
		ClusterRoleLabelAggregationKeyNode(key),
	)
}

const (
	// TODO: Compile these constants into the DSL authz model directly
	TypeUser                  = "user"
	TypeGroup                 = "group"
	TypeClusterRole           = "clusterrole"
	TypeClusterRoleBinding    = "clusterrolebinding"
	TypeNamespacedRole        = "role"
	TypeNamespacedRoleBinding = "rolebinding"
	TypeNamespace             = "namespace"
	// TODO: this should be called resource collection or something like object and collection scoped terminology
	TypeResource                    = "resource"
	TypeNonResource                 = "nonresourceurls"
	TypeClusterRoleLabelAggregation = "clusterrole_label"
	TypeResourceInstance            = "resourceinstance"

	RBACMatchAllVerbs = rbacv1.VerbAll
	// RBACMatchAllNonResources = rbacv1.NonResourceAll

	// ZanzibarMatchAllNonResources = "/*"
	RelationResourceAnyVerb = "anyverb"

	// RelationClusterRoleLabelSelector specifies the relation when "clusterrole:edit#assignee selects clusterrole_label:aggregate-to-edit=true"
	// TODO: Unify these with the other ZanzibarRelation... names
	RelationClusterRoleLabelSelector = "selects"
	// RelationClusterRoleAssignee specifies the relation between some kind of user, group or userset of user or group type, e.g.
	// - "user:lucas assignee clusterrole:foo"
	// - "group:admin assignee clusterrole:admin"
	// - "clusterrole_label:aggregate-to-edit=true#selected assignee clusterrole:my-aggregated-edit-role"
	// - "clusterrole:admin#assignee assignee clusterrole:view"
	RelationClusterRoleAssignee = "assignee"
	// RelationNamespacedRoleAssignee defines what relation a user and group can have to the role, in order to be matched for getting privileges
	// like read and write access to namespaced APIs, e.g.
	// - "role:foo#assignee is related to resource:core.pods as get"
	RelationNamespacedRoleAssignee           = "assignee"
	RelationNamespacedRoleNamespacedAssignee = "namespaced_assignee"

	// RelationNamespaceContainsRole defines the relation between a role and its namespace
	RelationNamespaceContainsRole = "contains"

	ContextualRelationWildcardMatch       = "wildcardmatch"
	ContextualRelationOperatesInNamespace = "operates_in"
	ContextualRelationResourceMatch       = "resourcematch"
	ContextualRelationUserInGroup         = "members"

	APIGroupKubernetesCore = "core"
	KindClusterRole        = "ClusterRole"
	KindClusterRoleBinding = "ClusterRoleBinding"
	KindRole               = "Role"
)

var (
	// "approve", "sign", "attest" verbs are used by the Certificate Signing Request APIs and their respective admission controllers, asking the authorizer
	// if the given user should have access the synthetic "signers" resource in the certificates.k8s.io group, for a specific resource name, in this usage
	// signer, specified in the API object. As there are no examples of "collection-level" SubjectAccessReviews (SAR) for any signer (or resourcename), we here
	// make these instance relations ONLY. That is, asking a SubjectAccessReview with name="" is considered invalid and returns NoDecision.

	// "impersonate" verb is checked in staging/src/k8s.io/apiserver/pkg/endpoints/filters/impersonation.go; and always contains a resource name too; so
	// lets not define the verb such that nobody can check if they can impersonate anyone, but actually have to ask "can I impersonate this person?".

	// See staging/src/k8s.io/apiserver/pkg/endpoints/openapi/openapi.go for a list of verbs
	// See kubectl can-i code for client side verbs: staging/src/k8s.io/kubectl/pkg/cmd/create/create_role.go
	// Also see pkg/apis/flowcontrol/validation/validation.go for a comprehensive list of the 9 verbs supported by the API server

	// Apparently /api/v1/watch/pods is a thing? It works though. Source: staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo_test.go

	// nodes' proxy verb (not subresource) remains a mysterium. Maybe I need to try a kubeadm installation and curl using -X PROXY?

	// TODO: distinguish between what can be asked for in authorizer or specified in RBAC
	InstanceRelationsOnly   = sets.New[string]() // TODO: "impersonate", "approve", "sign", "attest" // These are not used in the API server, only in Authorizer APIs/SARs
	CollectionRelationsOnly = sets.New("list", "create", "deletecollection")
	CommonRelations         = sets.New("get", "watch", "update", "patch", "delete") // TODO: Do we have to add "proxy" as well?

	InstanceRelations   = InstanceRelationsOnly.Union(CommonRelations)
	CollectionRelations = CollectionRelationsOnly.Union(CommonRelations)

	ResourceRelations    = CommonRelations.Union(InstanceRelationsOnly).Union(CollectionRelationsOnly)
	NonResourceRelations = sets.New("get")
)
