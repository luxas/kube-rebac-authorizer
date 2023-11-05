// Credits: This file is inspired by https://github.com/kubernetes-sigs/controller-runtime/blob/v0.16.3/pkg/webhook/authentication/webhook.go,
// but for SubjectAccessReview.

package authzwebhook

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	authorizationv1 "k8s.io/api/authorization/v1"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Request defines the input for an authorization handler.
// It contains information to identify the object in
// question (group, version, kind, resource, subresource,
// name, namespace), as well as the operation in question
// (e.g. Get, Create, etc), and the object itself.
type Request struct {
	authorizationv1.SubjectAccessReview
}

// Response is the output of an authorization handler.
// It contains a response indicating if a given
// operation is allowed.
type Response struct {
	authorizationv1.SubjectAccessReview
}

// Handler can handle an TokenReview.
type Handler interface {
	// Handle yields a response to an TokenReview.
	//
	// The supplied context is extracted from the received http.Request, allowing wrapping
	// http.Handlers to inject values into and control cancelation of downstream request processing.
	Handle(context.Context, Request) Response
}

// HandlerFunc implements Handler interface using a single function.
type HandlerFunc func(context.Context, Request) Response

var _ Handler = HandlerFunc(nil)

// Handle process the TokenReview by invoking the underlying function.
func (f HandlerFunc) Handle(ctx context.Context, req Request) Response {
	return f(ctx, req)
}

// Webhook represents each individual webhook.
type Webhook struct {
	// Handler actually processes an authentication request returning whether it was authenticated or unauthenticated,
	// and potentially patches to apply to the handler.
	Handler Handler

	// WithContextFunc will allow you to take the http.Request.Context() and
	// add any additional information such as passing the request path or
	// headers thus allowing you to read them from within the handler
	WithContextFunc func(context.Context, *http.Request) context.Context

	setupLogOnce sync.Once
	log          logr.Logger
}

// Handle processes TokenReview.
func (wh *Webhook) Handle(ctx context.Context, req Request) Response {
	// The authentication webhook completed the response here, but we don't need to do that,
	// as there is no shared context between the request and response (probably there should be)
	return wh.Handler.Handle(ctx, req)
}

// getLogger constructs a logger from the injected log and LogConstructor.
func (wh *Webhook) getLogger(req *Request) logr.Logger {
	wh.setupLogOnce.Do(func() {
		if wh.log.GetSink() == nil {
			wh.log = logf.Log.WithName("authorization")
		}
	})

	return logConstructor(wh.log, req)
}

// logConstructor adds some commonly interesting fields to the given logger.
func logConstructor(base logr.Logger, req *Request) logr.Logger {
	if req != nil {
		if attrs := req.Spec.ResourceAttributes; attrs != nil {
			return base.WithValues(
				"verb", attrs.Verb,
				"apiGroup", attrs.Group,
				"resource", attrs.Resource,
				"subresource", attrs.Subresource,
				"namespace", attrs.Namespace,
				"name", attrs.Name,
				"user", req.Spec.User,
				"groups", strings.Join(req.Spec.Groups, ","),
			)
		}
		if attrs := req.Spec.NonResourceAttributes; attrs != nil {
			return base.WithValues(
				"verb", attrs.Verb,
				"path", attrs.Path,
				"user", req.Spec.User,
				"groups", strings.Join(req.Spec.Groups, ","),
			)
		}
	}
	return base
}
