package openfga

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/luxas/kube-rebac-authorizer/pkg/nodeauth"
	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"gotest.tools/v3/golden"
)

func TestBuildAuthorizationModel(t *testing.T) {
	as := rbacconversion.GetSchema()
	nodeas := nodeauth.GetSchema()
	as.Types = append(as.Types, nodeas.Types...)
	got := BuildAuthorizationModel(as)

	marshalled, err := protojson.Marshal(got)
	assert.NoError(t, err)

	buf := &bytes.Buffer{}
	assert.NoError(t, json.Indent(buf, marshalled, "", "  "))
	t.Log(buf.String())
	golden.Assert(t, buf.String(), "declarative-model.json")

	marshalledDSL, err := transformer.TransformJSONProtoToDSL(got)
	assert.NoError(t, err)

	golden.Assert(t, marshalledDSL, "declarative-model.fga")
}
