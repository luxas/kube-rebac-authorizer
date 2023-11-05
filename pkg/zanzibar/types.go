package zanzibar

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
)

type Checker interface {
	// CheckOne performs one check request for the given tuple.
	// The checker is bound to a given authorization schema.
	// Contextual tuples are added to all individual check requests.
	CheckOne(ctx context.Context, tuple Tuple, contextualTuples []Tuple) (bool, error)
}

// TupleStore is a store bound to a specific authorization model (TODO: can the model
// change over time?) and set of tuples.
type TupleStore interface {
	// ReadTuples reads all tuples from the store matching the following predicates:
	// - if tuple.User is set, then the
	ReadTuples(ctx context.Context, filter TupleFilter) ([]Tuple, error)
	// WriteTuples TODO
	WriteTuples(ctx context.Context, writes, deletes []Tuple) error
	// GetAuthorizationSchema gets the current authorization schema
	// TODO: Should this be a no-op without ctx and errors?
	GetAuthorizationSchema(ctx context.Context) (*AuthorizationSchema, error)
}

// TupleFilter contains predicates which filter tuples in the TupleStore.
// If all predicates are empty, all tuples in the store are returned.
type TupleFilter struct {
	// UserType filter matches all tuples with the given user type.
	UserType string
	// UserName filter matches all tuples with the given user type and name.
	// If UserName is set, UserType is mandatory. If UserName is empty,
	// _any_ user is returned. If UserName is TupleFilterWildcardUserName,
	// tuples which apply simultaneously to _all_ users are returned.
	UserName string
	// UserSetRelation matches all tuples with the given user type and name,
	// together with the given userset relation as the user. For example,
	// UserType=group, UserName=foo, UserSetRelation=members matches all tuples
	// where all group members of group foo are matched.
	// If UserSetRelation=TupleFilterWildcardUserSetRelation, then a union of all
	// tuples from all possible userset relations are returned.
	// If this is set, UserName and UserType are mandatory. However, UserName cannot
	// be TupleFilterWildcardUserName when UserSetRelation is non-empty.
	UserSetRelation string

	// Relation filter matches tuples only with the given relation.
	// If empty, tuples with any relation are returned.
	Relation string

	// ObjectType filter matches all tuples with the given object type.
	ObjectType string
	// ObjectName filter matches all tuples with the given object type and name.
	// If ObjectName is set, ObjectType is mandatory. If ObjectName is empty,
	// all tuples of the given type with any name is returned. As object nodes
	// cannot be usersets, there is no functionality related to usersets supported.
	ObjectName string
}

var (
	errUserTypeRequiredForUserName                    = errors.New("UserType required when when UserName is set")
	errUserNameRequiredForUserSetRelation             = errors.New("UserName required when when UserSetRelation is set")
	errObjectTypeRequiredForObjectName                = errors.New("ObjectType required when when ObjectName is set")
	errObjectNameWildcardExclusiveWithUserSetRelation = errors.New("UserSetRelation cannot be a wildcard when UserName is a wildcard")
)

func (tf TupleFilter) Validate() error {
	errs := []error{}
	if len(tf.UserName) != 0 && len(tf.UserType) == 0 {
		errs = append(errs, errUserTypeRequiredForUserName)
	}
	if len(tf.UserSetRelation) != 0 && len(tf.UserName) == 0 {
		errs = append(errs, errUserNameRequiredForUserSetRelation)
	}
	if len(tf.ObjectName) != 0 && len(tf.ObjectType) == 0 {
		errs = append(errs, errObjectTypeRequiredForObjectName)
	}
	if tf.UserName == TupleFilterWildcardUserName && len(tf.UserSetRelation) != 0 {
		errs = append(errs, errObjectNameWildcardExclusiveWithUserSetRelation)
	}
	return errors.Join(errs...)
}

const (
	TupleFilterWildcardUserName        = "*"
	TupleFilterWildcardUserSetRelation = "*"
)

func NewTuple(userType, userName, relation, objectType, objectName string) Tuple {
	return Tuple{
		User:     NewNode(userType, userName),
		Relation: relation,
		Object:   NewNode(objectType, objectName),
	}
}

func NewUserSetTuple(userType, userName, userSetRelation, relation, objectType, objectName string) Tuple {
	return Tuple{
		User:     NewNode(userType, userName).WithUserSet(userSetRelation),
		Relation: relation,
		Object:   NewNode(objectType, objectName),
	}
}

type Tuple struct {
	// User might be casted to UserSet, too
	// User might be nil if the tuple is empty
	User     Node
	Relation string
	Object   Node
}

func (t Tuple) Valid() bool {
	return t.User != nil && len(t.Relation) != 0 && t.Object != nil
}

func (t Tuple) GetUserSet() (us UserSet, hasUserSet bool) {
	us, hasUserSet = ToUserSet(t.User)
	return
}

// GetUserSetRelation gets t.User.UserSetRelation() if t.User is an UserSet,
// otherwise returns an empty string.
func (t Tuple) GetUserSetRelation() string {
	us, hasUserSet := t.GetUserSet()
	if hasUserSet {
		return us.UserSetRelation()
	}
	return ""
}

func ToUserSet(n Node) (us UserSet, ok bool) {
	if n == nil {
		return nil, false
	}
	us, ok = n.(UserSet)
	return
}

func IsUserSet(n Node) bool {
	_, ok := ToUserSet(n)
	return ok
}

func PrintTuples(tuples Tuples) string {
	str := "\n"
	for _, tuple := range tuples {
		if us, ok := ToUserSet(tuple.User); ok {
			str += fmt.Sprintf("\tzanzibar.NewUserSetTuple(%q, %q, %q, %q, %q, %q),\n",
				us.NodeType(),
				us.NodeName(),
				us.UserSetRelation(),
				tuple.Relation,
				tuple.Object.NodeType(),
				tuple.Object.NodeName())
			continue
		}

		str += fmt.Sprintf("\tzanzibar.NewTuple(%q, %q, %q, %q, %q),\n",
			tuple.User.NodeType(),
			tuple.User.NodeName(),
			tuple.Relation,
			tuple.Object.NodeType(),
			tuple.Object.NodeName())
	}
	return str
}

// Tuples is a typed Tuples slice that supports sorting using sort.Sort
type Tuples []Tuple

// Len is part of sort.Interface.
func (t Tuples) Len() int {
	return len(t)
}

// Swap is part of sort.Interface.
func (t Tuples) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

// Less is part of sort.Interface.
func (t Tuples) Less(i, j int) bool {
	return sortOrderString(&t[i]) < sortOrderString(&t[j])
}

func (t Tuples) Equals(other Tuples) bool {
	sort.Sort(t)
	sort.Sort(other)
	return reflect.DeepEqual(t, other)
}

func (t Tuples) AssertEqualsWanted(wanted Tuples, tt *testing.T, testName string) {
	// TODO: Diff only those tuples that are not equal
	if !t.Equals(wanted) {
		tt.Errorf("%s = %v, want %v", testName, PrintTuples(t), PrintTuples(wanted))
	}
}

func sortOrderString(t *Tuple) string {
	if us, ok := t.GetUserSet(); ok {
		return fmt.Sprintf("%s:%s#%s:%s:%s:%s", us.NodeType(), us.NodeName(), us.UserSetRelation(), t.Relation, t.Object.NodeType(), t.Object.NodeName())
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s", t.User.NodeType(), t.User.NodeName(), t.Relation, t.Object.NodeType(), t.Object.NodeName())
}
