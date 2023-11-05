# RBAC reconciliation

Upon API server startup, it creates default RBAC rules, **if the RBAC authorizer is enabled**.
These rules are more or less required for Kubernetes controllers themselves to have access to the required things, and for commonly-expected operations to work. That's why we want those rules in our case as well, as we still use RBAC rules as the "source of truth".

However, when we demo running the API server without RBAC, there will be no ClusterRoles reconciled to etcd by the API server. That's why I wanted to vendor that code into this project. However, at the moment this code exists as a poststarthook in `kubernetes/pkg/registry/rbac/rest/storage_rbac.go`, which if we vendor this, we vendor essentially the whole Kubernetes project, which is not fun to do, essentially not in a project we where we want to show how to innovate outside of Kubernetes :D

I extracted the relevant code from `storage_rbac.go` and put it here. The dependencies of this package are not, bad, 5 packages or si. I think this small refactor could be done upstream, but I'll check with sig-auth what they think. Until that, I carry this code here. I have attached the Kubernetes license in this folder; this file is **not** covered by the kube-rebac-authorizer's license.
