package openfga

import (
	"sort"

	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

func BuildAuthorizationModel(as zanzibar.AuthorizationSchema) *openfgav1.AuthorizationModel {
	typedefs := make(map[string]*openfgav1.TypeDefinition, len(as.Types))

	for _, typerelation := range as.Types {

		thistype := getOrCreateTypeDefinition(typedefs, typerelation.TypeName)

		for _, incoming := range typerelation.Incoming {

			// Append the relation to the type; for now only directly assignable
			userSet := getOrCreateUserSet(thistype, incoming.Relation)
			if userSet.Userset == nil { // TODO: if not, add to union or create union
				userSet.Userset = &openfgav1.Userset_This{
					This: &openfgav1.DirectUserset{},
				}
			}

			relationMeta := getOrCreateRelationMetadata(thistype.Metadata, incoming.Relation)

			if !util.Has(relationMeta.DirectlyRelatedUserTypes, func(rr *openfgav1.RelationReference) bool {
				return rr.Type == incoming.UserType && rr.GetRelation() == incoming.UserSetRelation
			}) {
				// make sure the type we reference will exist in the model, added after processing
				getOrCreateTypeDefinition(typedefs, incoming.UserType)

				rr := &openfgav1.RelationReference{
					Type: incoming.UserType,
				}
				if len(incoming.UserSetRelation) != 0 {
					rr.RelationOrWildcard = &openfgav1.RelationReference_Relation{
						Relation: incoming.UserSetRelation,
					}
				}
				relationMeta.DirectlyRelatedUserTypes = append(relationMeta.DirectlyRelatedUserTypes, rr)
			}
		}

		for _, outgoing := range typerelation.Outgoing {

			for _, relation := range outgoing.Relations {
				objectType := getOrCreateTypeDefinition(typedefs, outgoing.ObjectType)

				// Append the relation to the object type; for now only directly assignable
				userSet := getOrCreateUserSet(objectType, relation)
				if userSet.Userset == nil { // TODO: if not, add to union or create union
					userSet.Userset = &openfgav1.Userset_This{
						This: &openfgav1.DirectUserset{},
					}
				}

				relationMeta := getOrCreateRelationMetadata(objectType.Metadata, relation)

				if !util.Has(relationMeta.DirectlyRelatedUserTypes, func(rr *openfgav1.RelationReference) bool {
					return rr.Type == thistype.Type && rr.GetRelation() == outgoing.UserSetRelation
				}) {

					rr := &openfgav1.RelationReference{
						Type: thistype.Type,
					}
					if len(outgoing.UserSetRelation) != 0 {
						rr.RelationOrWildcard = &openfgav1.RelationReference_Relation{
							Relation: outgoing.UserSetRelation,
						}
					}
					relationMeta.DirectlyRelatedUserTypes = append(relationMeta.DirectlyRelatedUserTypes, rr)
				}
			}

		}
	}

	for _, typerelation := range as.Types {
		thistype := getOrCreateTypeDefinition(typedefs, typerelation.TypeName)

		for relation, evaluserset := range typerelation.EvaluatedUsersets {
			userset := getOrCreateUserSet(thistype, relation)
			wanted := userSetToOpenFGA(evaluserset)

			if userset.Userset == nil {
				userset.Userset = wanted.Userset
			} else if union := userset.GetUnion(); union != nil {
				// if there is already a union, just add wanted
				union.Child = append(union.Child, wanted)
			} else if union := wanted.GetUnion(); union != nil {
				// add the existing thing to the union and write wanted to the main
				union.Child = append([]*openfgav1.Userset{userset}, union.Child...)
				thistype.Relations[relation] = wanted
			} else {
				union := &openfgav1.Userset{
					Userset: &openfgav1.Userset_Union{
						Union: &openfgav1.Usersets{
							Child: []*openfgav1.Userset{userset, wanted},
						},
					},
				}

				thistype.Relations[relation] = union
			}
		}
	}

	typeDefSlice := make(sortableTypeDefinitions, 0, len(typedefs))
	for _, typedef := range typedefs {
		typeDefSlice = append(typeDefSlice, typedef)
	}

	sort.Sort(typeDefSlice)

	return &openfgav1.AuthorizationModel{
		SchemaVersion:   "1.1", // TODO: constant somewhere?
		TypeDefinitions: typeDefSlice,
	}
}

func userSetToOpenFGA(us zanzibar.EvaluatedUserset) *openfgav1.Userset {
	if len(us.Union) != 0 {
		return &openfgav1.Userset{
			Userset: &openfgav1.Userset_Union{
				Union: &openfgav1.Usersets{
					Child: util.Map(us.Union, userSetToOpenFGA),
				},
			},
		}
	}

	if len(us.Intersection) != 0 {
		return &openfgav1.Userset{
			Userset: &openfgav1.Userset_Intersection{
				Intersection: &openfgav1.Usersets{
					Child: util.Map(us.Intersection, userSetToOpenFGA),
				},
			},
		}
	}

	if us.Difference != nil {
		return &openfgav1.Userset{
			Userset: &openfgav1.Userset_Difference{
				Difference: &openfgav1.Difference{
					Base:     userSetToOpenFGA(us.Difference.Base),
					Subtract: userSetToOpenFGA(us.Difference.Subtract),
				},
			},
		}
	}

	if len(us.Relation) != 0 {
		return &openfgav1.Userset{
			Userset: &openfgav1.Userset_ComputedUserset{
				ComputedUserset: &openfgav1.ObjectRelation{
					Relation: us.Relation,
				},
			},
		}
	}

	if us.TupleToUserset != nil {
		return &openfgav1.Userset{
			Userset: &openfgav1.Userset_TupleToUserset{
				TupleToUserset: &openfgav1.TupleToUserset{
					Tupleset: &openfgav1.ObjectRelation{
						Relation: us.TupleToUserset.FromRelation,
					},
					ComputedUserset: &openfgav1.ObjectRelation{
						Relation: us.TupleToUserset.ReferencedRelation,
					},
				},
			},
		}
	}

	// TODO: This "shouldn't" happen
	return &openfgav1.Userset{} // Empty
}

type sortableTypeDefinitions []*openfgav1.TypeDefinition

func (s sortableTypeDefinitions) Len() int {
	return len(s)
}
func (s sortableTypeDefinitions) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortableTypeDefinitions) Less(i, j int) bool {
	return s[i].Type < s[j].Type
}

func getOrCreateTypeDefinition(typedefs map[string]*openfgav1.TypeDefinition, typeName string) *openfgav1.TypeDefinition {
	typedef, ok := typedefs[typeName]
	if ok {
		return typedef
	}

	typedef = &openfgav1.TypeDefinition{
		Type:      typeName,
		Relations: make(map[string]*openfgav1.Userset),
		Metadata: &openfgav1.Metadata{
			Relations: make(map[string]*openfgav1.RelationMetadata),
		},
	}
	typedefs[typeName] = typedef
	return typedef
}

func getOrCreateUserSet(td *openfgav1.TypeDefinition, relation string) *openfgav1.Userset {
	userSet, ok := td.Relations[relation]
	if ok {
		return userSet
	}
	userSet = &openfgav1.Userset{}
	td.Relations[relation] = userSet
	return userSet
}

func getOrCreateRelationMetadata(m *openfgav1.Metadata, relation string) *openfgav1.RelationMetadata {
	relationMeta, ok := m.Relations[relation]
	if ok {
		return relationMeta
	}
	relationMeta = &openfgav1.RelationMetadata{
		DirectlyRelatedUserTypes: []*openfgav1.RelationReference{},
	}
	m.Relations[relation] = relationMeta
	return relationMeta
}
