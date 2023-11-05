package openfga_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/luxas/kube-rebac-authorizer/pkg/openfga"
	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"gotest.tools/v3/golden"
	"k8s.io/apimachinery/pkg/util/sets"
)

type Tuple = zanzibar.Tuple

func TestAuthzModel(t *testing.T) {
	authzmodel, err := transformer.TransformDSLToJSON(testAuthzModel)
	if err != nil {
		t.Error(t)
		return
	}

	marshalled, err := protojson.Marshal(authzmodel)
	assert.NoError(t, err)

	buf := &bytes.Buffer{}
	assert.NoError(t, json.Indent(buf, marshalled, "", "  "))
	t.Log(buf.String())
	golden.AssertBytes(t, buf.Bytes(), "test-authz-model.json")
}

func TestGetOutgoingRelationTypesFor(t *testing.T) {
	authzmodel, err := transformer.TransformDSLToJSON(testAuthzModel)
	if err != nil {
		t.Error(err)
		return
	}

	tests := []struct {
		targetTypeName       string
		directs              sets.Set[string]
		typesThroughUsersets map[string]sets.Set[string]
		wildcards            sets.Set[string]
	}{
		{
			targetTypeName: "user",
			wildcards:      sets.New("group"),
			directs:        sets.New("group", "namespace", "rolebinding"),
		},
		{
			targetTypeName: "group",
			typesThroughUsersets: map[string]sets.Set[string]{
				"namespace":   sets.New("members"),
				"rolebinding": sets.New("members"),
			},
		},
		{
			targetTypeName: "namespace",
			directs:        sets.New("role"),
		},
		{
			targetTypeName: "rolebinding",
			typesThroughUsersets: map[string]sets.Set[string]{
				"role": sets.New("namespaced_assignee"),
			},
		},
		{
			targetTypeName: "role",
			typesThroughUsersets: map[string]sets.Set[string]{
				"resource": sets.New("assignee"),
			},
		},
		{
			targetTypeName: "resource",
			directs:        sets.New("resource"),
		},
		{
			targetTypeName: "notexist",
		},
		{
			targetTypeName: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.targetTypeName, func(t *testing.T) {
			got := openfga.GetOutgoingRelationTypesFor(authzmodel, tt.targetTypeName)
			if tt.directs != nil {
				assert.True(t, tt.directs.Equal(got.Directs))
			}
			if tt.typesThroughUsersets != nil {
				want2 := string(util.Must(json.Marshal(tt.typesThroughUsersets)))
				got2 := string(util.Must(json.Marshal(got.TypesThroughUsersets)))
				if want2 != got2 {
					t.Errorf("GetOutgoingRelationTypesFor().TypesThroughUsersets: got: %s, want: %s", got2, want2)
				}
			}
			if tt.wildcards != nil {
				assert.True(t, tt.wildcards.Equal(got.Wildcards))
			}
		})
	}
}
