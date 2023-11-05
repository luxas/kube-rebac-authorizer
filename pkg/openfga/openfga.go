package openfga

import (
	"context"
	"fmt"

	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/tuple"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TODO: Add migration steps to the database

// Before I was using the buf.build/gen/go/openfga/api/grpc/go/openfga/v1/openfgav1grpc
// import, but that is not compatible with the openfga/language repository.

// TODO: make multi-store-aware?
func NewStoreAgnosticClient(cc grpc.ClientConnInterface) *StoreAgnosticClient { // TODO: check for conn=nil here?
	return &StoreAgnosticClient{
		fgaClient: openfgav1.NewOpenFGAServiceClient(cc),
	}
}

type Tuple = zanzibar.Tuple

type StoreAgnosticClient struct {
	// interface for all OpenFGA interaction
	fgaClient openfgav1.OpenFGAServiceClient
}

func (c *StoreAgnosticClient) WithStore(ctx context.Context, storeName string) (*AuthorizationModeller, error) {
	stores, err := c.fgaClient.ListStores(ctx, &openfgav1.ListStoresRequest{})
	if err != nil {
		return nil, err
	}

	matchingStores := util.Filter(stores.Stores, func(store *openfgav1.Store) bool {
		return store.Name == storeName
	})
	if len(matchingStores) > 1 {
		return nil, fmt.Errorf("more than one store with name %s", storeName)
	}

	if len(matchingStores) == 1 {
		return &AuthorizationModeller{
			storeID:   matchingStores[0].Id,
			fgaClient: c.fgaClient,
		}, nil
	}

	// TODO: Somehow one can make as many stores with the same name as wanted?
	// That is why we do a list first, instead of just trying to create and catching an AlreadyExists error
	resp, err := c.fgaClient.CreateStore(ctx, &openfgav1.CreateStoreRequest{
		Name: storeName,
	})
	if err != nil {
		return nil, err
	}
	return &AuthorizationModeller{
		storeID:   resp.Id,
		fgaClient: c.fgaClient,
	}, nil
}

type AuthorizationModeller struct {
	storeID string
	// interface for all OpenFGA interaction
	fgaClient openfgav1.OpenFGAServiceClient
}

func (am *AuthorizationModeller) WithAuthorizationSchema(ctx context.Context, as zanzibar.AuthorizationSchema) (*TupleStoreAndChecker, error) {

	authzmodel := BuildAuthorizationModel(as)

	// TODO: Make it possible to do a semantic diff of authorization schemas instead of writing every time.

	modelresp, err := am.fgaClient.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         am.storeID,
		TypeDefinitions: authzmodel.TypeDefinitions,
		SchemaVersion:   authzmodel.SchemaVersion,
	})
	if err != nil {
		return nil, err
	}

	return &TupleStoreAndChecker{
		storeID:   am.storeID,
		as:        as,
		fgaClient: am.fgaClient,
		authzModel: openfgav1.AuthorizationModel{
			Id:              modelresp.AuthorizationModelId,
			SchemaVersion:   authzmodel.SchemaVersion,
			TypeDefinitions: authzmodel.TypeDefinitions,
		},
	}, nil
}

var _ zanzibar.Checker = &TupleStoreAndChecker{}
var _ zanzibar.TupleStore = &TupleStoreAndChecker{}

type TupleStoreAndChecker struct {
	// TODO: Do we need this?
	//cc         grpc.ClientConnInterface

	// all check requests are sent to this store
	storeID string

	// TODO: make this auto-update?
	as         zanzibar.AuthorizationSchema
	authzModel openfgav1.AuthorizationModel
	// interface for all OpenFGA interaction
	fgaClient openfgav1.OpenFGAServiceClient
}

func (o *TupleStoreAndChecker) GetAuthorizationSchema(_ context.Context) (*zanzibar.AuthorizationSchema, error) {
	return &o.as, nil
}

func (o *TupleStoreAndChecker) StoreID() string { return o.storeID }

func (o *TupleStoreAndChecker) CheckOne(ctx context.Context, tuple Tuple, contextualTuples []Tuple) (bool, error) {

	clientContextualTuples := util.Map(contextualTuples, tupleToOpenFGA)

	resp, err := o.fgaClient.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              o.storeID,
		AuthorizationModelId: o.authzModel.Id,
		TupleKey:             tupleToOpenFGA(tuple),
		ContextualTuples: &openfgav1.ContextualTupleKeys{
			TupleKeys: clientContextualTuples,
		},
		// TODO: set up a docs for the tracing stack
		Trace: true,
	})
	if err != nil {
		return false, err
	}
	return resp.Allowed, nil
}

/*func (o *OpenFGAImpl) Read(ctx context.Context, writes, deletes []Tuple) error {
	// TODO: Pagination
	o.fgaClient.Read(ctx, &openfgav1.ReadRequest{})
	// o.fgaClient.ReadChanges(ctx, &openfgav1.ReadChangesRequest{
}*/

// TODO: Get this constant from openfga directly?
var maxPageSize = wrapperspb.Int32(100)

func (o *TupleStoreAndChecker) ReadTuples(ctx context.Context, filter zanzibar.TupleFilter) ([]Tuple, error) {

	// From the OpenFGA docs (https://openfga.dev/api/service#/Relationship%20Tuples/Read):
	// - tuple_key is optional. If not specified, it will return all tuples in the store.
	// - tuple_key.object is mandatory if tuple_key is specified.
	// 		It can be a full object (e.g., type:object_id) or type only (e.g., type:).
	// - tuple_key.user is mandatory if tuple_key is specified in the case the tuple_key.object is a type only.

	// In this code, we add support for filtering by a user or user set, without specifying any object.
	// However, we cannot support in this code the case when objectType is set but not objectName AND
	// there is no fully-qualified user node.

	if err := filter.Validate(); err != nil {
		return nil, err
	}

	hasUserType := len(filter.UserType) != 0
	hasUserName := len(filter.UserName) != 0
	hasObjectType := len(filter.ObjectType) != 0
	//hasObjectName := len(filter.ObjectName) != 0

	// We know from validation that if if userName is set, then userType is too.
	// But we don't support the case when userType is set, but not userName, either
	// both are set or empty
	if hasUserType && !hasUserName {
		// TODO: typed errors
		return nil, fmt.Errorf("must specify either both UserType and UserName or neither")
	}

	// Need special handling if a user node was specified, but no object at all
	requestFilters := []zanzibar.TupleFilter{}
	if hasUserType && hasUserName && !hasObjectType {
		// TODO: This could use the generic authorization schema too, but I don't know if it's any better.
		tp := GetOutgoingRelationTypesFor(&o.authzModel, filter.UserType)
		if filter.UserName == zanzibar.TupleFilterWildcardUserName {
			// query tuples for all types this type has a wildcard connection to
			for objectType := range tp.Wildcards {
				requestFilters = append(requestFilters, zanzibar.TupleFilter{
					UserType:   filter.UserType,
					UserName:   filter.UserName,
					Relation:   filter.Relation,
					ObjectType: objectType,
				})
			}
		} else if len(filter.UserSetRelation) == 0 {
			// find all direct relations from this user type.
			// username wildcard and usersetrelation non-empty are mutually exclusive
			for objectType := range tp.Directs {
				requestFilters = append(requestFilters, zanzibar.TupleFilter{
					UserType:   filter.UserType,
					UserName:   filter.UserName,
					Relation:   filter.Relation,
					ObjectType: objectType,
				})
			}
		} else { // UserSetRelation is non-empty, UserName not wildcard
			for objectType, relationSet := range tp.TypesThroughUsersets {
				for userSetRelation := range relationSet {
					// the relation matches the query if the query is a wildcard or equal
					if filter.UserSetRelation == userSetRelation || filter.UserSetRelation == zanzibar.TupleFilterWildcardUserSetRelation {
						requestFilters = append(requestFilters, zanzibar.TupleFilter{
							UserType:        filter.UserType,
							UserName:        filter.UserName,
							UserSetRelation: userSetRelation,
							Relation:        filter.Relation,
							ObjectType:      objectType,
						})
					}
				}
			}
		}
	} else {
		// either user node is not set at all, or user node is set and at least the object type,
		// so openfga supports this query "natively", just pass the parameter along
		requestFilters = append(requestFilters, filter)
	}

	result := []Tuple{}
	for _, currentFilter := range requestFilters {
		resp, err := o.readPaginated(ctx, &openfgav1.ReadRequest{
			StoreId:  o.storeID,
			TupleKey: tupleFilterToOpenFGA(&currentFilter),
			PageSize: maxPageSize,
		})
		if err != nil {
			return nil, err
		}
		result = append(result, util.MapNonNil(resp, openFGAToTuple)...)
	}

	return result, nil
}

func (o *TupleStoreAndChecker) readPaginated(ctx context.Context, rr *openfgav1.ReadRequest) ([]*openfgav1.Tuple, error) {
	result := []*openfgav1.Tuple{}
	resp, err := o.fgaClient.Read(ctx, rr)
	if err != nil {
		return nil, err
	}
	result = append(result, resp.Tuples...)

	for len(resp.ContinuationToken) != 0 {
		rr.ContinuationToken = resp.ContinuationToken
		resp, err = o.fgaClient.Read(ctx, rr)
		if err != nil {
			return nil, err
		}
		result = append(result, resp.Tuples...)
	}
	return result, nil
}

func (o *TupleStoreAndChecker) WriteTuples(ctx context.Context, writes, deletes []Tuple) error {
	// TODO: Max 10 tuples in total for deletes+writes; need pagination
	// TODO: The API is not idempotent; need to read first, then write
	writesLen := len(writes)
	deletesLen := len(deletes)
	totalLen := writesLen + deletesLen

	for i := 0; i < totalLen; {
		writesStart := min(i, writesLen)
		writesEnd := min(i+10, writesLen)

		deletesStart := min(max(i-writesLen, 0), deletesLen)
		deletesEnd := min(max(i-writesLen, -10)+10, deletesLen)

		req := &openfgav1.WriteRequest{
			StoreId:              o.storeID,
			AuthorizationModelId: o.authzModel.Id,
		}
		// need to set req.Writes and req.Deletions conditionally, otherwise
		// we get error:
		//	invalid WriteRequest.Deletes: embedded message failed validation | caused by: invalid TupleKeys.TupleKeys: value must contain at least 1 item(s)
		// if one of them would have an empty TupleKeys list
		if writesStart != writesEnd {
			req.Writes = &openfgav1.TupleKeys{
				TupleKeys: util.Map(writes[writesStart:writesEnd], tupleToOpenFGA),
			}
		}
		if deletesStart != deletesEnd {
			req.Deletes = &openfgav1.TupleKeys{
				TupleKeys: util.Map(deletes[deletesStart:deletesEnd], tupleToOpenFGA),
			}
		}

		_, err := o.fgaClient.Write(ctx, req)
		if err != nil {
			return err
		}

		i += writesEnd - writesStart
		i += deletesEnd - deletesStart
	}
	return nil
}

// TODO: Move to util
func min(i, j int) int {
	if i < j {
		return i
	}
	return j
}
func max(i, j int) int {
	if i < j {
		return j
	}
	return i
}

func tupleToOpenFGA(tuple Tuple) *openfgav1.TupleKey {
	userNodeString := nodeString(tuple.User.NodeType(), tuple.User.NodeName())
	if us, ok := tuple.GetUserSet(); ok {
		userNodeString = withUserSetRelation(userNodeString, us.UserSetRelation())
	}

	return &openfgav1.TupleKey{
		User:     userNodeString,
		Relation: tuple.Relation,
		Object:   nodeString(tuple.Object.NodeType(), tuple.Object.NodeName()),
	}
}

// tupleFilterToOpenFGA converts a tuple filter into a format OpenFGA understands
// IMPORTANT! UserSetRelation cannot be a wildcard here, the wildcard must be
// processed before by the caller, and only relations that exist in the model
// can be used.
func tupleFilterToOpenFGA(filter *zanzibar.TupleFilter) *openfgav1.TupleKey {
	u := nodeString(filter.UserType, filter.UserName)
	if len(filter.UserSetRelation) != 0 {
		u = withUserSetRelation(u, filter.UserSetRelation)
	}
	return &openfgav1.TupleKey{
		User:     u,
		Relation: filter.Relation,
		Object:   nodeString(filter.ObjectType, filter.ObjectName),
	}
}

// TODO: call the openfga tuple package?
func nodeString(typeName, nodeName string) string {
	if len(typeName) == 0 && len(nodeName) == 0 {
		return ""
	}
	return typeName + ":" + nodeName
}
func withUserSetRelation(nodeString, userSetRelation string) string {
	return nodeString + "#" + userSetRelation
}

func openFGAToTuple(t *openfgav1.Tuple) *Tuple {
	userNodeString, userSetRelation := tuple.SplitObjectRelation(t.Key.User)
	userType, userName := tuple.SplitObject(userNodeString)
	objectType, objectName := tuple.SplitObject(t.Key.Object)
	if len(userType) == 0 || len(userName) == 0 || len(t.Key.Relation) == 0 || len(objectType) == 0 || len(objectName) == 0 {
		return nil
	}

	userNode := zanzibar.NewNode(userType, userName)
	if len(userSetRelation) != 0 {
		userNode = userNode.WithUserSet(userSetRelation)
	}

	return &zanzibar.Tuple{
		User:     userNode,
		Relation: t.Key.Relation,
		Object:   zanzibar.NewNode(objectType, objectName),
	}
}
