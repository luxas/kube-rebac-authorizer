package authorizer

import (
	"context"
	"errors"
	"fmt"

	"github.com/luxas/kube-rebac-authorizer/pkg/nodeauth"
	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion"
	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// ReBACAuthorizer must implement Authorizer
var _ authorizer.Authorizer = &ReBACAuthorizer{}

type ReBACAuthorizer struct {
	Checker             zanzibar.Checker
	AuthorizationSchema zanzibar.AuthorizationSchema
}

const (
	RBACMatchAllAPIGroups = rbacv1.APIGroupAll
	RBACMatchAllResources = rbacv1.ResourceAll

	ContextualRelationWildcardMatch       = rbacconversion.ContextualRelationWildcardMatch
	ContextualRelationOperatesInNamespace = rbacconversion.ContextualRelationOperatesInNamespace
	ContextualRelationResourceMatch       = rbacconversion.ContextualRelationResourceMatch
)

var (
	resourceNodeFunc = rbacconversion.ResourceNode
)

type Tuple = zanzibar.Tuple

func (a *ReBACAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {

	// verify verb is supported
	if attrs.IsResourceRequest() {
		if len(attrs.GetName()) != 0 && !rbacconversion.InstanceRelations.Has(attrs.GetVerb()) {
			return authorizer.DecisionNoOpinion, "authorizer does not support instance resource verb: " + attrs.GetVerb(), nil
		} else if len(attrs.GetName()) == 0 && !rbacconversion.CollectionRelations.Has(attrs.GetVerb()) {
			return authorizer.DecisionNoOpinion, "authorizer does not support collection resource verb: " + attrs.GetVerb(), nil
		}
	} else if !attrs.IsResourceRequest() && !rbacconversion.NonResourceRelations.Has(attrs.GetVerb()) {
		return authorizer.DecisionNoOpinion, "authorizer does not support non-resource verb: " + attrs.GetVerb(), nil
	}

	user, contextualTuples := userNodeFor(attrs.GetUser())
	if user == nil {
		return authorizer.DecisionNoOpinion, "", nil
	}

	fullResource := attrs.GetResource()
	hasSubresource := false
	if len(attrs.GetSubresource()) != 0 {
		fullResource += "/" + attrs.GetSubresource()
		hasSubresource = true
	}
	resourceNode := resourceNodeFunc(attrs.GetAPIGroup(), fullResource)
	checkNode := resourceNode

	if attrs.IsResourceRequest() {
		// TODO: Is it worth caching this? Probably not?
		wildcardNodes := make([]zanzibar.Node, 0, 5)
		// this request matches resource:*.*
		wildcardNodes = append(wildcardNodes, resourceNodeFunc(RBACMatchAllAPIGroups, RBACMatchAllResources))
		// this request matches resource:{apiGroup}.*
		wildcardNodes = append(wildcardNodes, resourceNodeFunc(attrs.GetAPIGroup(), RBACMatchAllResources))
		// this request matches resource:*.{fullResource}
		wildcardNodes = append(wildcardNodes, resourceNodeFunc(RBACMatchAllAPIGroups, fullResource))

		// replicate behavior of rbacv1helpers.ResourceMatches; if this request is for a subresource,
		// then match an RBAC rule of the form *.*/{subresource} and {apiGroup}.*/{subresource} too
		// TODO: test this explicitly
		if hasSubresource {
			subresourceMatch := RBACMatchAllResources + "/" + attrs.GetSubresource()
			// this request matches resource:*.*/{subresource}
			wildcardNodes = append(wildcardNodes, resourceNodeFunc(RBACMatchAllAPIGroups, subresourceMatch))
			// this request matches resource:{apiGroup}.*/{subresource}
			wildcardNodes = append(wildcardNodes, resourceNodeFunc(attrs.GetAPIGroup(), subresourceMatch))
		}

		// add all these wildcard matches to the contextual tuples
		contextualTuples = append(contextualTuples, zanzibar.
			NewNodes(wildcardNodes...).WithRelation(ContextualRelationWildcardMatch).To(resourceNode)...)
	} else {
		fmt.Println("TODO")
		// TODO: handle non-resource request path lookups! and maybe split into two functions
	}

	// TODO: Add resource name support also using contextual tuples; not dedicated types (for now?)
	// TODO: Is namespace actually empty for cluster-wide resources?
	if len(attrs.GetNamespace()) != 0 {
		contextualTuples = append(contextualTuples, user.WithRelation(ContextualRelationOperatesInNamespace).ToOne(rbacconversion.NamespaceNode(attrs.GetNamespace())))
	}

	// Allow object-level authorization by adding a "forwarding" contextual tuple between the generic "get pods"
	// resource collection node to the "get pod foo-123" resource instance node; such that if the user has access
	// to all pods then they have access also to the specific pod foo-123 through the contextual tuple. However,
	// if the user does not have access to all pods, we still send the check request for the specifically asked
	// for instance of the resource, so that it is possible to activate (cluster)roles with resourceNames set.
	if len(attrs.GetName()) != 0 {
		// build the object-scoped node
		instanceresourceNode := rbacconversion.ResourceInstanceNode(attrs.GetAPIGroup(), attrs.GetResource(), attrs.GetName())
		// add forwarding from collection-scoped rules to the object-scoped one
		contextualTuples = append(contextualTuples, resourceNode.WithRelation(ContextualRelationResourceMatch).ToOne(instanceresourceNode))
		// perform the check request on the object-scoped resource. any collection rules will apply.
		checkNode = instanceresourceNode
	}

	// issue the check request
	allowed, err := a.Checker.CheckOne(ctx, user.WithRelation(attrs.GetVerb()).ToOne(checkNode), contextualTuples)
	if allowed {
		return authorizer.DecisionAllow, "", nil
	}

	// try to check it
	individualAllowed, individualErr := a.resolveIndividual(ctx, attrs, user, contextualTuples)
	if individualAllowed {
		return authorizer.DecisionAllow, "", nil
	}
	err = errors.Join(err, individualErr)

	reason := ""
	if err != nil { // TODO: How to not leak sensitive info here?
		reason = fmt.Sprintf("ReBAC error: %v", err)
	}
	return authorizer.DecisionNoOpinion, reason, nil
}

func (a *ReBACAuthorizer) resolveIndividual(ctx context.Context, attrs authorizer.Attributes, user zanzibar.Node, contextualTuples []zanzibar.Tuple) (bool, error) {
	// this requires a individual object
	if attrs.GetName() == "" {
		return false, nil
	}

	// Try to check for individual access
	gvk := toGVK(schema.GroupVersionResource{
		Group:    attrs.GetAPIGroup(),
		Version:  attrs.GetAPIVersion(),
		Resource: attrs.GetResource(),
	})
	typeName := nodeauth.GVKToTypeName(gvk)

	_, err := util.MatchOne(a.AuthorizationSchema.Types, func(tr zanzibar.TypeRelation) bool {
		return tr.TypeName == typeName
	})
	if err != nil {
		return false, nil // TODO: log error as it is a schema problem, but zero is not a problem
	}

	// TODO: Can we always rely on namespace being empty here for all non-namespaced resources?
	nodeID := nodeauth.GenericNodeID(attrs.GetNamespace(), attrs.GetName())

	checkNode := zanzibar.NewNode(typeName, nodeID)

	// TODO: figure out if the relation exists in the model before checking, to avoid it leaking to the user in the reason
	// Thus we ignore the error for now
	allowed, _ := a.Checker.CheckOne(ctx, user.WithRelation(attrs.GetVerb()).ToOne(checkNode), contextualTuples)
	if allowed {
		return true, nil
	}

	return false, nil
}

// userNodeFor returns the starting user node, and contextual tuples linking the user node to
// other nodes policy might be written for, such as groups
// if the user is not found, the returned node will be nil
func userNodeFor(u user.Info) (zanzibar.Node, []Tuple) {
	// Fail-fast if username is not set, let's require this for now
	if len(u.GetName()) == 0 {
		return nil, nil
	}
	// TODO: Can we use the UID somehow or are we stuck with names?
	contextualTuples := make([]Tuple, 0, len(u.GetGroups()))
	userNode := rbacconversion.UserNode(u.GetName())
	for _, g := range u.GetGroups() {
		contextualTuples = append(contextualTuples, userNode.WithRelation(rbacconversion.ContextualRelationUserInGroup).ToOne(rbacconversion.GroupNode(g)))
	}
	return userNode, contextualTuples
}

// TODO: real lookup implementation
func toGVK(gvr schema.GroupVersionResource) schema.GroupVersionKind {
	kind := ""
	switch gvr.Resource {
	case "nodes":
		kind = "Node"
	case "pods":
		kind = "Pod"
	case "secrets":
		kind = "Secret"
	}
	return schema.GroupVersionKind{
		Group:   gvr.Group,
		Version: gvr.Version,
		Kind:    kind,
	}
}
