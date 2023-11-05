package zanzibar

import "github.com/luxas/kube-rebac-authorizer/pkg/util"

// Node points to only exactly one node. The node has a type
// and name. The node can be transformed into a user set, meaning it
// becomes a query which matches all users related to the given node
// (with type NodeType() and name NodeName()) through UserSetRelation().
// The Node can be related to one or multiple other nodes producing
// tuples, through providing a relation.
type Node interface {
	// NodeType specifies the node type name.
	NodeType() string
	// NodeName specifies the name of the node of NodeType type.
	// Any two nodes with the same NodeType and NodeName are considered
	// equal. Two nodes of distinct types with the same name are not equal.
	// TODO: Talk about ID and Type only instead?
	NodeName() string

	// WithUserSet transforms the node into a userset query.
	// As UserSet also embeds Node, calling WithUserSet on a
	// UserSet overwrites the previous UserSetRelation.
	WithUserSet(userSetRelation string) UserSet
	WithRelation(relation string) RelatedNode
}

func NodeValid(n Node) bool {
	return len(n.NodeType()) != 0 && len(n.NodeName()) != 0
}

// UserSet points to all nodes related as users in tuples
// where AbstractNode is the object, and NodeSetRelation is the
// relation.
type UserSet interface {
	Node
	UserSetRelation() string
}

// RelatedNodes contains one or multiple user or userset nodes, and a relation,
// which can be related with the given objects nodes to produce tuples.
//
// It is invalid to provide any UserSet nodes as objects, however, no errors
// are produced, but UserSetRelation() is ignored.
// Any invalid nodes where either NodeType or NodeName are empty are ignored.
type RelatedNodes interface {
	To(objects ...Node) []Tuple
}

// RelatedNode represents exactly one user node and a relation,
// which can be related with the given one or multiple object nodes to produce tuples.
//
// It is invalid to provide any UserSet nodes as objects, however, no errors
// are produced, but UserSetRelation() is ignored.
// Any invalid nodes where either NodeType or NodeName are empty are ignored.
type RelatedNode interface {
	RelatedNodes
	ToOne(object Node) Tuple
}

// Nodes represents one or more nodes that can be related to other
// nodes through a relation.
type Nodes interface {
	// GetNodes return the underlying slice of nodes.
	GetNodes() []Node
	WithRelation(relation string) RelatedNodes
	// WithUserSet maps all nodes to UserSets using the
	// the Node WithUserSet function.
	WithUserSet(userSetRelation string) UserSets
}

// UserSets represents a set of usersets that can be related to
// other nodes through a relation.
type UserSets interface {
	GetUserSets() []UserSet
	WithRelation(relation string) RelatedNodes
}

func NewNode(nodeType, nodeName string) Node {
	return node{nodeType, nodeName}
}

var _ Node = node{}

type node [2]string

func (n node) NodeType() string { return n[0] }
func (n node) NodeName() string { return n[1] }
func (n node) WithRelation(r string) RelatedNode {
	return relatedNode{n, r}
}
func (n node) WithUserSet(userSetRelation string) UserSet {
	return userSet{n[0], n[1], userSetRelation}
}

var _ UserSet = userSet{}

type userSet [3]string

func (us userSet) NodeType() string        { return us[0] }
func (us userSet) NodeName() string        { return us[1] }
func (us userSet) UserSetRelation() string { return us[2] }
func (us userSet) WithUserSet(userSetRelation string) UserSet {
	return userSet{us[0], us[1], userSetRelation}
}
func (us userSet) WithRelation(r string) RelatedNode {
	return relatedNode{us, r}
}

var _ RelatedNode = relatedNode{}

type relatedNode struct {
	n        Node
	relation string
}

func (rn relatedNode) To(objects ...Node) []Tuple {
	tuples := make([]Tuple, 0, len(objects))
	for _, obj := range objects {
		if !NodeValid(obj) {
			continue
		}

		tuples = append(tuples, rn.ToOne(obj))
	}
	return tuples
}

func (rn relatedNode) ToOne(object Node) Tuple {
	if !NodeValid(object) {
		return Tuple{}
	}

	return Tuple{
		User:     rn.n,
		Relation: rn.relation,
		Object:   object,
	}
}

func NewNodes(n ...Node) Nodes {
	return nodes(n)
}

var _ Nodes = nodes{}

type nodes []Node

func (n nodes) GetNodes() []Node { return n }
func (n nodes) WithRelation(tupleRelation string) RelatedNodes {
	return relatedNodes[Node]{n, tupleRelation}
}
func (n nodes) WithUserSet(userSetRelation string) UserSets {
	// TODO: What if userSetRelation is empty?
	return userSets(util.Map(n, func(n Node) UserSet {
		return n.WithUserSet(userSetRelation)
	}))
}

var _ UserSets = userSets{}

type userSets []UserSet

func (us userSets) GetUserSets() []UserSet { return us }
func (us userSets) WithRelation(tupleRelation string) RelatedNodes {
	return relatedNodes[UserSet]{us, tupleRelation}
}

var _ RelatedNodes = relatedNodes[node]{}
var _ RelatedNodes = relatedNodes[userSet]{}

type relatedNodes[T Node] struct {
	nodes         []T
	tupleRelation string
}

func (ur relatedNodes[T]) To(objects ...Node) []Tuple {
	tuples := make([]Tuple, 0, len(ur.nodes)*len(objects))
	for _, u := range ur.nodes {
		for _, obj := range objects {
			tuples = append(tuples, Tuple{
				User:     u,
				Relation: ur.tupleRelation,
				Object:   obj,
			})
		}
	}
	return tuples
}
