package zanzibar

import (
	context "context"

	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"k8s.io/apimachinery/pkg/util/sets"
)

// Reconcile computes a reconcile for all tuples related to the given node. Old tuples are deleted, new tuples added,
// and existing tuples not touched. The first tuple slice returned are the tuples that should be added, the second
// for tuples to be deleted. Use ReconcileApply for applying them at the same time.
// TODO: This would reconcile almost all tuples twice, once from the "user side" and once from the "object side"
// How do we specify what side is the "authorative" or "producing" side to respect?
// TODO: Move this to the generic Zanzibar library as we won't depend on specific stuff in OpenFGA.
func ReconcileCompute(ctx context.Context, s TupleStore, node Node, desiredTuples []Tuple) ([]Tuple, []Tuple, error) {
	// There are three ways to be related to node, by the node being
	// - a subject user
	// - a subject userset
	// - an object
	// But due to limitations in the OpenFGA API, we need to do more work with the authorization model.

	as, err := s.GetAuthorizationSchema(ctx)
	if err != nil {
		return nil, nil, err
	}

	matchedType, err := util.MatchOne(as.Types, func(tr TypeRelation) bool {
		return tr.TypeName == node.NodeType()
	})
	if err != nil {
		return nil, nil, err
	}

	ownedIncomingRelations := sets.New[typeUserset]()
	ownedOutgoingRelations := sets.New[typeUserset]()

	for _, incoming := range matchedType.Incoming {
		ownedIncomingRelations.Insert(typeUserset{
			TypeName:        incoming.UserType,
			UserSetRelation: incoming.UserSetRelation,
		})
	}
	for _, outgoing := range matchedType.Outgoing {
		ownedOutgoingRelations.Insert(typeUserset{
			TypeName:        outgoing.ObjectType,
			UserSetRelation: outgoing.UserSetRelation,
		})
	}

	// For example, a ClusterRole does not know to which all ClusterRoleBinding it is the object in Tuples such as:
	// clusterrolebinding:foo1#assignee, assignee, clusterrole:foo
	// clusterrolebinding:foo2#assignee, assignee, clusterrole:foo
	// This relation is defined as outgoing for clusterrolebinding, but NOT incoming on the clusterrole side
	// So if we did a full search for all tuples with clusterrole:foo as object when reconciling clusterrole
	// tuples, we'd get the above tuples to "remove" as they are not generated from the clusterrole object and
	// thus not likely part of the desiredTuples.
	// TODO: Add validation when building the authorizationschema that there are no conflicts/dupicates between
	// incoming and outgoing relations between types, or do we support both?
	// TODO: Need to change UserSetRelations to become a slice of ORed values?

	incomingTuples, err := s.ReadTuples(ctx, TupleFilter{
		ObjectType: node.NodeType(),
		ObjectName: node.NodeName(),
	})
	if err != nil {
		return nil, nil, err
	}

	incomingTuples = util.Filter(incomingTuples, func(t Tuple) bool {
		return ownedIncomingRelations.Has(typeUserset{
			TypeName:        t.User.NodeType(),
			UserSetRelation: t.GetUserSetRelation(),
		})
	})

	// Get all tuples where this subject node is related to any other typed node
	// through any direct relation.
	outgoingUserTuples, err := s.ReadTuples(ctx, TupleFilter{
		UserType: node.NodeType(),
		UserName: node.NodeName(),
	})
	if err != nil {
		return nil, nil, err
	}

	// Get all tuples where this subject node is related to any other typed node
	// through any userset relation and any relation.
	outgoingUserSetTuples, err := s.ReadTuples(ctx, TupleFilter{
		UserType:        node.NodeType(),
		UserName:        node.NodeName(),
		UserSetRelation: TupleFilterWildcardUserSetRelation,
	})
	if err != nil {
		return nil, nil, err
	}

	outgoingTuples := append(outgoingUserTuples, outgoingUserSetTuples...)

	outgoingTuples = util.Filter(outgoingTuples, func(t Tuple) bool {
		return ownedOutgoingRelations.Has(typeUserset{
			TypeName:        t.Object.NodeType(),
			UserSetRelation: t.GetUserSetRelation(),
		})
	})

	tupleLookup := map[Tuple][2]int{}
	var tuplesToAdd []*Tuple
	var tuplesToRemove []*Tuple

	for i, tuple := range incomingTuples {
		tupleLookup[tuple] = [2]int{directionIn, i}
	}
	for i, tuple := range outgoingTuples {
		tupleLookup[tuple] = [2]int{directionOut, i}
	}

	alreadyExistsTupleIndices := sets.New[[2]int]()

	for i, desiredTuple := range desiredTuples {
		whereToFind, exists := tupleLookup[desiredTuple]
		if !exists {
			// Register a new desired tuple that we want to add
			tuplesToAdd = append(tuplesToAdd, &desiredTuples[i])
			continue
		}
		// register that this desired tuple already exists in OpenFGA
		alreadyExistsTupleIndices.Insert(whereToFind)
	}

	// TODO: Could we effectively shrink these instead in the above loop, to yield
	// just the tuples for deletion in the end?
	for i := range incomingTuples {
		if !alreadyExistsTupleIndices.Has([2]int{directionIn, i}) {
			tuplesToRemove = append(tuplesToRemove, &incomingTuples[i])
		}
	}

	for i := range outgoingTuples {
		if !alreadyExistsTupleIndices.Has([2]int{directionOut, i}) {
			tuplesToRemove = append(tuplesToRemove, &outgoingTuples[i])
		}
	}

	return util.DereferenceList(tuplesToAdd), util.DereferenceList(tuplesToRemove), nil
}

func ReconcileApply(ctx context.Context, s TupleStore, node Node, desiredTuples []Tuple) error {
	additions, deletions, err := ReconcileCompute(ctx, s, node, desiredTuples)
	if err != nil {
		return err
	}
	return s.WriteTuples(ctx, additions, deletions)
}

const (
	directionIn  = 1
	directionOut = 2
)

type typeUserset struct {
	TypeName        string
	UserSetRelation string
}
