package zanzibar

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/luxas/kube-rebac-authorizer/pkg/util"
)

type AuthorizationSchema struct {
	Types []TypeRelation
}

type (
	ObjectIDExprFunc func(obj any, relation string) ([]string, error)
	UserIDExprFunc   func(obj any) ([]string, error)
	IDExprFunc       func(obj any) (string, error)
	ConditionFunc    func(obj any) bool
)

type TypeRelation struct {
	TypeName string
	IDExpr   IDExprFunc
	EscapeID bool

	Condition ConditionFunc

	Outgoing []OutgoingRelation
	Incoming []IncomingRelation

	EvaluatedUsersets map[string]EvaluatedUserset
}

// TODO: Make this for all other places too
// Maybe call EscapeID QueryEscapeID
func (tr *TypeRelation) GetID(obj any) (string, error) {
	if tr.IDExpr == nil {
		return "", nil
	}

	nodeID, err := tr.IDExpr(obj)
	if err != nil {
		return "", err
	}

	if tr.EscapeID {
		nodeID = url.QueryEscape(nodeID)
	}
	return nodeID, nil
}

// EvaluatedUserset specifies a set of mutually
// exclusive options
// TODO: Add validation and "empty" functions
type EvaluatedUserset struct {
	// Set operations
	Union        []EvaluatedUserset
	Intersection []EvaluatedUserset
	Difference   *DifferenceUserset

	// Relation points to a relation being "inherited" (Computed Userset)
	Relation       string
	TupleToUserset *TupleToUserset
}

type DifferenceUserset struct {
	Base     EvaluatedUserset
	Subtract EvaluatedUserset
}

type TupleToUserset struct {
	// The relation being referenced in the foreign type
	ReferencedRelation string
	// The relation in the main type pointing to the foreign type
	FromRelation string
}

type OutgoingRelation struct {
	ObjectType      string
	UserSetRelation string
	Relations       []string

	ObjectIDExpr ObjectIDExprFunc
	Condition    ConditionFunc

	EscapeID bool
}

type IncomingRelation struct {
	UserType        string
	UserSetRelation string
	Relation        string

	UserIDExpr UserIDExprFunc
	Condition  ConditionFunc

	EscapeID bool
}

func CastIDExpr[T any](f func(obj T) (string, error)) IDExprFunc {
	return func(obj any) (string, error) {
		casted, ok := obj.(T)
		if !ok {
			return "", fmt.Errorf("castIDExpr: %w, got type: %T, want to cast to: %T", ErrCouldNotCastType, obj, *new(T))
		}
		return f(casted)
	}
}

func CastIncoming[T any](f func(obj T) ([]string, error)) UserIDExprFunc {
	return func(obj any) ([]string, error) {
		casted, ok := obj.(T)
		if !ok {
			return nil, fmt.Errorf("castIncoming: %w, got type: %T, want to cast to: %T", ErrCouldNotCastType, obj, *new(T))
		}
		return f(casted)
	}
}
func CastOutgoing[T any](f func(obj T, relation string) ([]string, error)) ObjectIDExprFunc {
	return func(obj any, relation string) ([]string, error) {
		casted, ok := obj.(T)
		if !ok {
			return nil, fmt.Errorf("castOutgoing: %w, got type: %T, want to cast to: %T", ErrCouldNotCastType, obj, *new(T))
		}
		return f(casted, relation)
	}
}

var ErrCouldNotCastType = errors.New("could not cast object to correct type")

func GenerateTuplesFor(tr TypeRelation, obj any) ([]Tuple, error) {
	// make sure the top-level condition is true
	if tr.Condition != nil && !tr.Condition(obj) {
		return nil, nil
	}

	if tr.TypeName == "" {
		return nil, fmt.Errorf("nodeType required") // TODO: Error or not?
	}

	nodeID, err := tr.GetID(obj)
	if err != nil {
		return nil, err
	}
	node := NewNode(tr.TypeName, nodeID)

	result := []Tuple{}

	for _, outgoing := range tr.Outgoing {
		for _, relation := range outgoing.Relations {
			// verify the condition
			if outgoing.Condition != nil && !outgoing.Condition(obj) {
				continue
			}

			if outgoing.ObjectIDExpr == nil {
				continue
			}

			objectIDs, err := outgoing.ObjectIDExpr(obj, relation)
			if err != nil {
				return nil, err
			}

			if outgoing.EscapeID {
				objectIDs = util.Map(objectIDs, url.QueryEscape)
			}

			objectIDs = util.FilterEmpty(objectIDs)

			objectNodes := util.Map(objectIDs, func(userID string) Node {
				return NewNode(outgoing.ObjectType, userID)
			})

			userNode := node
			if len(outgoing.UserSetRelation) != 0 {
				userNode = userNode.WithUserSet(outgoing.UserSetRelation)
			}

			result = append(result, userNode.WithRelation(relation).To(objectNodes...)...)
		}
	}

	for _, incoming := range tr.Incoming {
		// verify the condition
		if incoming.Condition != nil && !incoming.Condition(obj) {
			continue
		}

		if incoming.UserIDExpr == nil {
			continue
		}

		// TODO: verify func non-nil
		userIDs, err := incoming.UserIDExpr(obj)
		if err != nil {
			return nil, err
		}

		if incoming.EscapeID {
			userIDs = util.Map(userIDs, url.QueryEscape)
		}

		userIDs = util.FilterEmpty(userIDs)

		userNodes := util.Map(userIDs, func(userID string) Node {
			n := NewNode(incoming.UserType, userID)
			if len(incoming.UserSetRelation) != 0 {
				n = n.WithUserSet(incoming.UserSetRelation)
			}
			return n
		})

		result = append(result, NewNodes(userNodes...).WithRelation(incoming.Relation).To(node)...)
	}

	return result, nil
}
