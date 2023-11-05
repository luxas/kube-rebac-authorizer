package authzwebhook

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func NewWebhookForAuthorizer(authz authorizer.Authorizer) *Webhook {
	return &Webhook{
		Handler: HandlerFunc(func(ctx context.Context, req Request) Response {
			ar := authorizer.AttributesRecord{
				User: &user.DefaultInfo{
					Name:   req.Spec.User,
					UID:    req.Spec.UID,
					Groups: req.Spec.Groups,
					//Extra: req.Spec.Extra,
				},
			}

			if req.Spec.ResourceAttributes != nil && req.Spec.NonResourceAttributes != nil {
				return Denied("cannot specify both resource and non-resource attributes")
			}

			if attrs := req.Spec.ResourceAttributes; attrs != nil {
				ar.APIGroup = attrs.Group
				ar.APIVersion = attrs.Version
				ar.Name = attrs.Name
				ar.Namespace = attrs.Namespace
				ar.Resource = attrs.Resource
				ar.ResourceRequest = true
				ar.Subresource = attrs.Subresource
				ar.Verb = attrs.Verb
			}
			if attrs := req.Spec.NonResourceAttributes; attrs != nil {
				ar.Path = attrs.Path
				ar.ResourceRequest = true
				ar.Verb = attrs.Verb
			}

			decision, reason, err := authz.Authorize(ctx, ar)
			if err != nil {
				return Errored(err)
			}
			if decision == authorizer.DecisionAllow {
				return Allowed(reason)
			}
			if decision == authorizer.DecisionDeny {
				return Denied(reason)
			}
			return NoOpinion()
		}),
	}
}
