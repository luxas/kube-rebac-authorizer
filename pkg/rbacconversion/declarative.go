package rbacconversion

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

type GenericConverter struct {
}

func (GenericConverter) ConvertClusterRoleBindingToTuples(ctx context.Context, clusterrolebinding rbacv1.ClusterRoleBinding) ([]Tuple, error) {
	return zanzibar.GenerateTuplesFor(GetSchema().Types[0], clusterrolebinding)
}

func (GenericConverter) ConvertRoleBindingToTuples(ctx context.Context, rolebinding rbacv1.RoleBinding) ([]Tuple, error) {
	return zanzibar.GenerateTuplesFor(GetSchema().Types[1], rolebinding)
}

func (GenericConverter) ConvertRoleToTuples(ctx context.Context, role rbacv1.Role) ([]Tuple, error) {
	return zanzibar.GenerateTuplesFor(GetSchema().Types[2], role)
}

func (GenericConverter) ConvertClusterRoleToTuples(ctx context.Context, clusterrole rbacv1.ClusterRole) ([]zanzibar.Tuple, error) {
	return zanzibar.GenerateTuplesFor(GetSchema().Types[3], clusterrole)
}

func GetSchema() zanzibar.AuthorizationSchema {
	return zanzibar.AuthorizationSchema{
		Types: []zanzibar.TypeRelation{
			{ // TODO: Use a map instead of slice?
				TypeName:  TypeClusterRoleBinding, // rbacTypeName(KindClusterRoleBinding),
				Condition: castCondition(clusterRoleBindingCondition),
				IDExpr: zanzibar.CastIDExpr(func(crb rbacv1.ClusterRoleBinding) (string, error) {
					return crb.Name, nil
				}),
				EscapeID: true,
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType: TypeUser,
						Relation: RelationClusterRoleAssignee,

						UserIDExpr: zanzibar.CastIncoming(func(crb rbacv1.ClusterRoleBinding) ([]string, error) {
							return util.Map(
								util.Filter(crb.Subjects, func(s rbacv1.Subject) bool {
									return len(s.Name) != 0 &&
										((s.Kind == rbacv1.UserKind && s.APIGroup == rbacv1.GroupName) ||
											(s.Kind == rbacv1.ServiceAccountKind && s.APIGroup == "" && len(s.Namespace) != 0))
								}), func(s rbacv1.Subject) string {
									if s.Kind == rbacv1.UserKind {
										return s.Name
									} // else serviceaccount
									return serviceaccount.MakeUsername(s.Namespace, s.Name)
								}), nil
						}),
						EscapeID: true,
					},
					{
						UserType:        TypeGroup,
						UserSetRelation: ContextualRelationUserInGroup,
						Relation:        RelationClusterRoleAssignee,

						UserIDExpr: zanzibar.CastIncoming(func(crb rbacv1.ClusterRoleBinding) ([]string, error) {
							return util.Map(
								util.Filter(crb.Subjects, func(s rbacv1.Subject) bool {
									return s.Kind == rbacv1.GroupKind && s.APIGroup == rbacv1.GroupName
								}), func(s rbacv1.Subject) string {
									return s.Name
								}), nil
						}),
						EscapeID: true,
					},
				},
				Outgoing: []zanzibar.OutgoingRelation{
					{
						UserSetRelation: RelationClusterRoleAssignee,
						Relations:       []string{RelationClusterRoleAssignee},

						ObjectType: TypeClusterRole,
						ObjectIDExpr: zanzibar.CastOutgoing(func(crb rbacv1.ClusterRoleBinding, _ string) ([]string, error) {
							return []string{crb.RoleRef.Name}, nil
						}),
						EscapeID: true,
					},
				},
			},
			{
				TypeName:  TypeNamespacedRoleBinding,
				Condition: castCondition(roleBindingCondition),
				IDExpr: zanzibar.CastIDExpr(func(nrb rbacv1.RoleBinding) (string, error) {
					return namespacedEscapedID(nrb.Namespace, nrb.Name), nil
				}),
				EscapeID: false,
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType: TypeUser,
						Relation: RelationNamespacedRoleNamespacedAssignee,

						UserIDExpr: zanzibar.CastIncoming(func(nrb rbacv1.RoleBinding) ([]string, error) {
							return util.Map(
								util.Filter(nrb.Subjects, func(s rbacv1.Subject) bool { // TODO: Make this generic
									return len(s.Name) != 0 &&
										((s.Kind == rbacv1.UserKind && s.APIGroup == rbacv1.GroupName) ||
											(s.Kind == rbacv1.ServiceAccountKind && s.APIGroup == ""))
								}), func(s rbacv1.Subject) string {
									if s.Kind == rbacv1.UserKind {
										return s.Name
									} // else serviceaccount
									// default the namespace to namespace we're working in if it's available. This allows rolebindings that reference
									// SAs in the local namespace to avoid having to qualify them.
									saNamespace := nrb.Namespace
									if len(s.Namespace) > 0 {
										saNamespace = s.Namespace
									}
									if len(saNamespace) == 0 {
										return "" // skip, this is filtered out
									}

									return serviceaccount.MakeUsername(saNamespace, s.Name)
								}), nil
						}),
						EscapeID: true,
					},
					{
						UserType:        TypeGroup,
						UserSetRelation: ContextualRelationUserInGroup,
						Relation:        RelationNamespacedRoleNamespacedAssignee,

						UserIDExpr: zanzibar.CastIncoming(func(nrb rbacv1.RoleBinding) ([]string, error) {
							return util.Map(
								util.Filter(nrb.Subjects, func(s rbacv1.Subject) bool {
									return s.Kind == rbacv1.GroupKind && s.APIGroup == rbacv1.GroupName
								}), func(s rbacv1.Subject) string {
									return s.Name
								}), nil
						}),
						EscapeID: true,
					},
				},
				Outgoing: []zanzibar.OutgoingRelation{
					{
						UserSetRelation: RelationNamespacedRoleNamespacedAssignee,
						Relations:       []string{RelationNamespacedRoleNamespacedAssignee},

						ObjectType: TypeNamespacedRole,
						ObjectIDExpr: zanzibar.CastOutgoing(func(nrb rbacv1.RoleBinding, _ string) ([]string, error) {
							return []string{namespacedEscapedID(nrb.Namespace, nrb.RoleRef.Name)}, nil
						}),
						EscapeID: false,
					},
				},
			},
			{
				TypeName: TypeNamespacedRole,
				IDExpr: zanzibar.CastIDExpr(func(nr rbacv1.Role) (string, error) {
					return namespacedEscapedID(nr.Namespace, nr.Name), nil
				}),
				EscapeID: false,
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType: TypeNamespace,
						Relation: RelationNamespaceContainsRole,

						UserIDExpr: zanzibar.CastIncoming(func(nr rbacv1.Role) ([]string, error) {
							return []string{nr.Namespace}, nil
						}),
						EscapeID: true,
					},
				},
				Outgoing: []zanzibar.OutgoingRelation{
					{
						UserSetRelation: RelationNamespacedRoleAssignee,
						Relations:       append(CollectionRelations.UnsortedList(), RelationResourceAnyVerb),

						ObjectType: TypeResource,
						ObjectIDExpr: zanzibar.CastOutgoing(func(nr rbacv1.Role, relation string) ([]string, error) {
							return util.FlatMap(util.Filter(nr.Rules, func(pr rbacv1.PolicyRule) bool { // get only those policyrules that have the given verb
								verb := relation
								if relation == "anyverb" {
									verb = RBACMatchAllVerbs
								}
								return sets.New(pr.Verbs...).Has(verb) && len(pr.ResourceNames) == 0
							}), func(pr rbacv1.PolicyRule) []string {
								return util.FlatMap(pr.APIGroups, func(apiGroup string) []string {
									if apiGroup == "" {
										apiGroup = APIGroupKubernetesCore
									}
									return util.Map(pr.Resources, func(resource string) string {
										return apiGroup + "." + resource
									})
								})
							}), nil
						}),
						EscapeID: false,
					},
					{
						UserSetRelation: RelationNamespacedRoleAssignee,
						Relations:       append(InstanceRelations.UnsortedList(), RelationResourceAnyVerb),

						ObjectType: TypeResourceInstance,
						// TODO: Should we use pointers here?
						ObjectIDExpr: zanzibar.CastOutgoing(func(nr rbacv1.Role, relation string) ([]string, error) {
							return util.FlatMap(util.Filter(nr.Rules, func(pr rbacv1.PolicyRule) bool { // get only those policyrules that have the given verb
								verb := relation
								if relation == "anyverb" {
									verb = RBACMatchAllVerbs
								}
								return sets.New(pr.Verbs...).Has(verb) && len(pr.ResourceNames) != 0
							}), func(pr rbacv1.PolicyRule) []string {
								return util.FlatMap(pr.APIGroups, func(apiGroup string) []string {
									if apiGroup == "" {
										apiGroup = APIGroupKubernetesCore
									}
									return util.FlatMap(pr.Resources, func(resource string) []string {
										return util.Map(pr.ResourceNames, func(resourceName string) string {
											return apiGroup + "." + resource + "/" + url.QueryEscape(resourceName)
										})
									})
								})
							}), nil
						}),
						EscapeID: false,
					},
				},
				EvaluatedUsersets: map[string]zanzibar.EvaluatedUserset{
					RelationNamespacedRoleAssignee: {
						Intersection: []zanzibar.EvaluatedUserset{
							{
								Relation: RelationNamespacedRoleNamespacedAssignee,
							},
							{
								TupleToUserset: &zanzibar.TupleToUserset{
									ReferencedRelation: ContextualRelationOperatesInNamespace,
									FromRelation:       RelationNamespaceContainsRole,
								},
							},
						},
					},
				},
			},
			{
				TypeName: TypeClusterRole,
				IDExpr: zanzibar.CastIDExpr(func(cr rbacv1.ClusterRole) (string, error) {
					return cr.Name, nil
				}),
				EscapeID: true,
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType:        TypeClusterRoleLabelAggregation,
						UserSetRelation: RelationClusterRoleLabelSelector,
						Relation:        RelationClusterRoleAssignee,

						UserIDExpr: zanzibar.CastIncoming(func(cr rbacv1.ClusterRole) ([]string, error) {
							returned := []string{}
							for k, v := range cr.Labels {
								if k == "kubernetes.io/bootstrapping" {
									continue
								}
								// specifies the relation when e.g. "clusterrole_label:aggregate-to-edit=true#selected assignee clusterrole:my-aggregated-edit-role" and
								// the "exists" variant for labelexpressions "clusterrole_label:aggregate-to-edit#selected assignee clusterrole:my-aggregated-edit-role"
								returned = append(returned, k)
								returned = append(returned, k+"="+v)
							}
							return returned, nil
						}),
						EscapeID: false,
					},
				},
				Outgoing: []zanzibar.OutgoingRelation{
					{
						UserSetRelation: RelationClusterRoleAssignee,
						Relations:       []string{RelationClusterRoleLabelSelector},
						ObjectType:      TypeClusterRoleLabelAggregation,
						Condition: castCondition(func(cr rbacv1.ClusterRole) bool {
							return cr.AggregationRule != nil
						}),
						ObjectIDExpr: zanzibar.CastOutgoing(func(cr rbacv1.ClusterRole, _ string) ([]string, error) {
							returned := []string{}
							for _, selector := range cr.AggregationRule.ClusterRoleSelectors {

								// Convert any MatchLabels into the more generic MatchExpressions, according to the MatchLabels godoc:
								// "matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions,
								// whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed. +optional"
								for k, v := range selector.MatchLabels {
									selector.MatchExpressions = append(selector.MatchExpressions, metav1.LabelSelectorRequirement{
										Key:      k,
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{v},
									})
								}

								if len(selector.MatchExpressions) == 1 {
									expr := selector.MatchExpressions[0]
									// TODO: Should the key and key-value be separate relations?
									if expr.Operator == metav1.LabelSelectorOpIn {
										for _, val := range expr.Values {
											// all assignees of this cluster role now select the clusterrole aggregation label
											returned = append(returned, expr.Key+"="+val)
										}
									} else if expr.Operator == metav1.LabelSelectorOpExists {
										// all assignees of this cluster role now select the clusterrole aggregation label
										returned = append(returned, expr.Key)
									} else {
										fmt.Println("Unsupported label expression operator!") // TODO
									}
								} else if len(selector.MatchExpressions) > 0 {
									// We cannot perform AND expressions in OpenFGA, yet at least.
									fmt.Println("Cannot handle MatchExpressions!") // TODO
								}
							}
							return returned, nil
						}),
					},
					{
						UserSetRelation: RelationClusterRoleAssignee,
						Relations:       []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "anyverb"},

						ObjectType: TypeResource, // TODO: Put condition that aggregationrule is not set here?
						ObjectIDExpr: zanzibar.CastOutgoing(func(cr rbacv1.ClusterRole, relation string) ([]string, error) {
							return util.FlatMap(util.Filter(cr.Rules, func(pr rbacv1.PolicyRule) bool { // get only those policyrules that have the given verb
								verb := relation
								if relation == "anyverb" {
									verb = RBACMatchAllVerbs
								}
								return sets.New(pr.Verbs...).Has(verb) && len(pr.ResourceNames) == 0
							}), func(pr rbacv1.PolicyRule) []string {
								return util.FlatMap(pr.APIGroups, func(apiGroup string) []string {
									if apiGroup == "" {
										apiGroup = APIGroupKubernetesCore
									}
									return util.Map(pr.Resources, func(resource string) string {
										return apiGroup + "." + resource
									})
								})
							}), nil
						}),
						EscapeID: false,
					},
					{
						UserSetRelation: RelationClusterRoleAssignee,
						Relations:       []string{"get", "watch", "update", "patch", "delete", "anyverb"},

						ObjectType: TypeResourceInstance,
						ObjectIDExpr: zanzibar.CastOutgoing(func(cr rbacv1.ClusterRole, relation string) ([]string, error) {
							return util.FlatMap(util.Filter(cr.Rules, func(pr rbacv1.PolicyRule) bool { // get only those policyrules that have the given verb
								verb := relation
								if relation == "anyverb" {
									verb = RBACMatchAllVerbs
								}
								return sets.New(pr.Verbs...).Has(verb) && len(pr.ResourceNames) != 0
							}), func(pr rbacv1.PolicyRule) []string {
								return util.FlatMap(pr.APIGroups, func(apiGroup string) []string {
									if apiGroup == "" {
										apiGroup = APIGroupKubernetesCore
									}
									return util.FlatMap(pr.Resources, func(resource string) []string {
										return util.Map(pr.ResourceNames, func(resourceName string) string {
											return apiGroup + "." + resource + "/" + url.QueryEscape(resourceName)
										})
									})
								})
							}), nil
						}),
					},
					{
						UserSetRelation: RelationClusterRoleAssignee,
						Relations:       []string{"get", "anyverb"},

						ObjectType: TypeNonResource,
						ObjectIDExpr: zanzibar.CastOutgoing(func(cr rbacv1.ClusterRole, relation string) ([]string, error) {
							return util.FlatMap(util.Filter(cr.Rules, func(pr rbacv1.PolicyRule) bool { // get only those policyrules that have the given verb
								verb := relation
								if relation == "anyverb" {
									verb = RBACMatchAllVerbs
								}
								return sets.New(pr.Verbs...).Has(verb) // TODO: Filter for nonResourceURLs exclusitivity?
							}), func(pr rbacv1.PolicyRule) []string {
								return util.Map(pr.NonResourceURLs, func(nonResourceURL string) string {
									if !strings.HasPrefix(nonResourceURL, "/") {
										nonResourceURL = "/" + nonResourceURL
									}
									return nonResourceURL
								})
							}), nil
						}),
					},
				},
			},
			{
				TypeName: TypeGroup,
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType: TypeUser,
						Relation: ContextualRelationUserInGroup,
					},
				},
			},
			{
				TypeName: TypeNamespace,
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType: TypeUser,
						Relation: ContextualRelationOperatesInNamespace,
					},
					{
						UserType:        TypeGroup,
						Relation:        ContextualRelationOperatesInNamespace,
						UserSetRelation: ContextualRelationUserInGroup,
					},
				},
			},
			{
				TypeName: TypeResource,
				Outgoing: []zanzibar.OutgoingRelation{
					{
						ObjectType: TypeResource,
						Relations:  []string{ContextualRelationWildcardMatch},
					},
				},
				EvaluatedUsersets: map[string]zanzibar.EvaluatedUserset{
					"get":              orWildcardRelationOrParent("get", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
					"list":             orWildcardRelationOrParent("list", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
					"watch":            orWildcardRelationOrParent("watch", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
					"create":           orWildcardRelationOrParent("create", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
					"update":           orWildcardRelationOrParent("update", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
					"patch":            orWildcardRelationOrParent("patch", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
					"delete":           orWildcardRelationOrParent("delete", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
					"deletecollection": orWildcardRelationOrParent("deletecollection", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
				},
			},
			{
				TypeName: TypeResourceInstance,
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType: TypeResource,
						Relation: ContextualRelationResourceMatch,
					},
				},
				EvaluatedUsersets: map[string]zanzibar.EvaluatedUserset{
					RelationResourceAnyVerb: orParent(RelationResourceAnyVerb, ContextualRelationResourceMatch),
					"get":                   orWildcardRelationOrParent("get", RelationResourceAnyVerb, ContextualRelationResourceMatch),
					"watch":                 orWildcardRelationOrParent("watch", RelationResourceAnyVerb, ContextualRelationResourceMatch),
					"update":                orWildcardRelationOrParent("update", RelationResourceAnyVerb, ContextualRelationResourceMatch),
					"patch":                 orWildcardRelationOrParent("patch", RelationResourceAnyVerb, ContextualRelationResourceMatch),
					"delete":                orWildcardRelationOrParent("delete", RelationResourceAnyVerb, ContextualRelationResourceMatch),
				},
			},
			{
				TypeName: TypeNonResource,
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType: TypeNonResource,
						Relation: ContextualRelationWildcardMatch,
					},
				},
				EvaluatedUsersets: map[string]zanzibar.EvaluatedUserset{
					RelationResourceAnyVerb: orParent(RelationResourceAnyVerb, ContextualRelationWildcardMatch),
					"get":                   orWildcardRelationOrParent("get", RelationResourceAnyVerb, ContextualRelationWildcardMatch),
				},
			},
		},
	}
}

func orParent(relationName, toParentRelation string) zanzibar.EvaluatedUserset {
	return zanzibar.EvaluatedUserset{
		TupleToUserset: &zanzibar.TupleToUserset{
			ReferencedRelation: relationName,
			FromRelation:       toParentRelation,
		},
	}
}

func orWildcardRelationOrParent(relationName, wildcardRelation, toParentRelation string) zanzibar.EvaluatedUserset {
	return zanzibar.EvaluatedUserset{
		Union: []zanzibar.EvaluatedUserset{
			{
				Relation: wildcardRelation,
			},
			orParent(relationName, toParentRelation),
		},
	}
}

func castCondition[T any](f func(obj T) bool) zanzibar.ConditionFunc {
	return func(obj any) bool {
		casted, ok := obj.(T)
		if !ok {
			return false
		}
		return f(casted)
	}
}

/*func metadataName() zanzibar.IDExprFunc {
	return zanzibar.CastIDExpr(func(o metav1.Object) (string, error) {
		return o.GetName(), nil
	})
}*/

func namespacedEscapedID(namespace, name string) string {
	return namespace + "/" + url.QueryEscape(name)
}

func clusterRoleBindingCondition(crb rbacv1.ClusterRoleBinding) bool {
	// force the reference to be to an RBAC ClusterRole
	if crb.RoleRef.APIGroup != rbacv1.GroupName {
		return false
	}
	if crb.RoleRef.Kind != KindClusterRole {
		return false
	}
	return len(crb.RoleRef.Name) != 0 // Does RBAC enforce this?
}

func roleBindingCondition(nrb rbacv1.RoleBinding) bool {
	// force the reference to be to an RBAC Role (for now)
	if nrb.RoleRef.APIGroup != rbacv1.GroupName {
		return false
	}
	// TODO: Assign a ClusterRole to a RoleBinding
	if nrb.RoleRef.Kind != KindRole {
		return false
	}
	return len(nrb.RoleRef.Name) != 0 // Does RBAC enforce this?
}

/*func rbacTypeName(kind string) string {
	return convertGroupKindToTypeName(rbacv1.SchemeGroupVersion.WithKind(kind).GroupKind())
}

func convertGroupKindToTypeName(gk schema.GroupKind) string {
	// from kubernetes/staging/src/k8s.io/apimachinery/pkg/util/validation/validation.go: the API group must be
	// "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character"
	//
	// also, kind must be RFC 1035:
	// "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character"
	//
	// We need to escape dots, as those are not allowed in OpenFGA type names.
	group := strings.ReplaceAll(gk.Group, ".", "_")
	if len(group) == 0 {
		group = APIGroupKubernetesCore
	}

	return "G_" + group + "_K_" + strings.ToLower(gk.Kind)
}*/
