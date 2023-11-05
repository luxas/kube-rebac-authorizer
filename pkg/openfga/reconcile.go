package openfga

import (
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

// GetOutgoingRelationTypesFor gets all types for which typeName has a direct relation
func GetOutgoingRelationTypesFor(model *openfgav1.AuthorizationModel, targetTypeName string) typeRelations {
	result := typeRelations{
		Wildcards:            sets.New[string](),
		Directs:              sets.New[string](),
		TypesThroughUsersets: map[string]sets.Set[string]{},
	}

	for _, typeDef := range model.GetTypeDefinitions() {
		if typeDef.GetMetadata() == nil {
			continue
		}
		for _, relationMeta := range typeDef.GetMetadata().GetRelations() {
			for _, refs := range relationMeta.GetDirectlyRelatedUserTypes() {
				if refs.GetType() == targetTypeName {
					if w := refs.GetWildcard(); w != nil {
						result.Wildcards.Insert(typeDef.Type)
						continue
					}
					if len(refs.GetRelation()) != 0 {

						existing, ok := result.TypesThroughUsersets[typeDef.Type]
						if ok {
							existing.Insert(refs.GetRelation())
						} else {
							result.TypesThroughUsersets[typeDef.Type] = sets.New(refs.GetRelation())
						}

						continue
					}
					result.Directs.Insert(typeDef.Type)
				}
			}
		}
	}

	return result
}

type typeRelations struct {
	// "I am related to all these types as wildcards"
	Wildcards sets.Set[string]
	// "I am related to all these types through this set of relations"
	TypesThroughUsersets map[string]sets.Set[string]
	// "I am related to all these types directly"
	Directs sets.Set[string]
}
