package nodeauth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func GVKToTypeName(gvk schema.GroupVersionKind) string {
	groupName := gvk.Group
	if groupName == "" {
		groupName = "core"
	}
	return fmt.Sprintf("%s.%s", groupName, strings.ToLower(gvk.Kind))
}

func GenericNodeID(namespace, name string) string {
	escapedName := url.QueryEscape(name)
	if len(namespace) == 0 {
		return escapedName
	}

	return url.QueryEscape(namespace) + "/" + escapedName
}

func GetSchema() *zanzibar.AuthorizationSchema {
	return &zanzibar.AuthorizationSchema{
		Types: []zanzibar.TypeRelation{
			{
				TypeName: "core.node",
				IDExpr: zanzibar.CastIDExpr(func(n *v1.Node) (string, error) {
					// TODO: This make this generic as it probably needs to be the same for every object; find if the type is namespaced or not from discovery
					// TODO: Try casting to client.Object again
					return GenericNodeID("", n.Name), nil
				}),
				EscapeID: false, // TODO: does this hold?
				Incoming: []zanzibar.IncomingRelation{
					/*{
						UserType:        "resourceinstance",
						UserSetRelation: "get",
						Relation:        "get",
						UserIDExpr: zanzibar.CastIncoming(func(n v1.Node) ([]string, error) {
							return []string{"core.nodes/" + url.QueryEscape(n.Name)}, nil
						}),
					},*/
					{ // TODO: How to avoid privilege escalation? Do we always want that a person that can see nodes shall be able to see all its referenced Pods?
						UserType: "user",
						Relation: "get",
						UserIDExpr: zanzibar.CastIncoming(func(n *v1.Node) ([]string, error) {
							return []string{url.QueryEscape("system:node:" + n.Name)}, nil
						}),
					},
				},
			},
			{
				TypeName: "core.pod",
				IDExpr: zanzibar.CastIDExpr(func(p *v1.Pod) (string, error) {
					return GenericNodeID(p.Namespace, p.Name), nil
				}),
				EscapeID: false, // TODO: does this hold?
				Incoming: []zanzibar.IncomingRelation{
					{
						UserType: "core.node",
						Relation: "node_to_pod",
						UserIDExpr: zanzibar.CastIncoming(func(p *v1.Pod) ([]string, error) {
							return []string{GenericNodeID("", p.Spec.NodeName)}, nil // TODO: Escaping?
						}),
					},
				},
				Outgoing: []zanzibar.OutgoingRelation{
					{
						ObjectType: "core.secret",
						Relations:  []string{"pod_to_secret"},
						ObjectIDExpr: zanzibar.CastOutgoing(func(p *v1.Pod, _ string) ([]string, error) {
							return util.FlatMap(p.Spec.Containers, func(c v1.Container) []string {
								return util.FlatMap(c.EnvFrom, func(env v1.EnvFromSource) []string {
									if env.SecretRef != nil {
										return []string{GenericNodeID(p.Namespace, env.SecretRef.Name)}
									}
									return nil
								})
							}), nil
						}),
					},
				},
				EvaluatedUsersets: map[string]zanzibar.EvaluatedUserset{
					"get": {
						TupleToUserset: &zanzibar.TupleToUserset{
							ReferencedRelation: "get",
							FromRelation:       "node_to_pod",
						},
					},
				},
			},
			{
				TypeName: "core.secret",
				EvaluatedUsersets: map[string]zanzibar.EvaluatedUserset{
					"get": {
						TupleToUserset: &zanzibar.TupleToUserset{
							ReferencedRelation: "get",
							FromRelation:       "pod_to_secret",
						},
					},
				},
			},
		},
	}
}
