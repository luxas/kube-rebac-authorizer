// Credits: This file is inspired by https://github.com/kubernetes-sigs/controller-runtime/blob/v0.16.3/pkg/webhook/authentication/http.go

package authzwebhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var authorizationScheme = runtime.NewScheme()
var authorizationCodecs = serializer.NewCodecFactory(authorizationScheme)

func init() {
	utilruntime.Must(authorizationv1.AddToScheme(authorizationScheme))
}

var _ http.Handler = &Webhook{}

func (wh *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	var err error
	ctx := r.Context()
	if wh.WithContextFunc != nil {
		ctx = wh.WithContextFunc(ctx, r)
	}

	var reviewResponse Response
	if r.Body == nil {
		err = errors.New("request body is empty")
		wh.getLogger(nil).Error(err, "bad request")
		reviewResponse = Errored(err)
		wh.writeResponse(w, nil, reviewResponse)
		return
	}

	defer r.Body.Close()
	if body, err = io.ReadAll(r.Body); err != nil {
		wh.getLogger(nil).Error(err, "unable to read the body from the incoming request")
		reviewResponse = Errored(err)
		wh.writeResponse(w, nil, reviewResponse)
		return
	}

	// verify the content type is accurate
	if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
		err = fmt.Errorf("contentType=%s, expected application/json", contentType)
		wh.getLogger(nil).Error(err, "unable to process a request with unknown content type")
		reviewResponse = Errored(err)
		wh.writeResponse(w, nil, reviewResponse)
		return
	}

	req := Request{}
	_, _, err = authorizationCodecs.UniversalDeserializer().Decode(body, nil, &req.SubjectAccessReview)
	if err != nil {
		wh.getLogger(nil).Error(err, "unable to decode the request")
		reviewResponse = Errored(err)
		wh.writeResponse(w, &req, reviewResponse)
		return
	}
	wh.getLogger(&req).V(5).Info("received request")

	reviewResponse = wh.Handle(ctx, req)
	wh.writeResponse(w, &req, reviewResponse)
}

// writeTokenResponse writes response resp to w. req is optional (can be nil) and adds
// context for the logger.
func (wh *Webhook) writeResponse(w io.Writer, req *Request, resp Response) {
	resp.SetGroupVersionKind(authorizationv1.SchemeGroupVersion.WithKind("SubjectAccessReview"))
	if err := json.NewEncoder(w).Encode(resp.SubjectAccessReview); err != nil {
		wh.getLogger(req).Error(err, "unable to encode the response")
		// avoid an infinite loop here
		// wh.writeResponse(w, Errored(err))
	}
	wh.getLogger(req).Info("wrote response", "allowed", resp.Status.Allowed, "denied", resp.Status.Denied)
}
