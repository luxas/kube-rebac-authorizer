/*
Copyright 2023. Luxas Labs Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/apiserver/pkg/server"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	// TODO: Reactivate when adding the CRD API
	// rebacv1alpha1 "github.com/luxas/kube-rebac-authorizer/api/v1alpha1"
	"github.com/luxas/kube-rebac-authorizer/internal/forked/kuberbacreconciliation"
	"github.com/luxas/kube-rebac-authorizer/pkg/authorizer"
	"github.com/luxas/kube-rebac-authorizer/pkg/authorizer/authzwebhook"
	"github.com/luxas/kube-rebac-authorizer/pkg/controllers/clusterrolebindingsyncer"
	"github.com/luxas/kube-rebac-authorizer/pkg/controllers/clusterrolesyncer"
	"github.com/luxas/kube-rebac-authorizer/pkg/controllers/genericsyncer"
	"github.com/luxas/kube-rebac-authorizer/pkg/controllers/rolebindingsyncer"
	"github.com/luxas/kube-rebac-authorizer/pkg/controllers/rolesyncer"
	"github.com/luxas/kube-rebac-authorizer/pkg/nodeauth"
	"github.com/luxas/kube-rebac-authorizer/pkg/openfga"
	"github.com/luxas/kube-rebac-authorizer/pkg/rbacconversion"
	"github.com/luxas/kube-rebac-authorizer/pkg/util"
	"github.com/luxas/kube-rebac-authorizer/pkg/zanzibar"
	"github.com/openfga/openfga/pkg/telemetry"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	// // TODO: Reactivate when adding the CRD API
	// utilruntime.Must(rebacv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var configFileFlag string
	flag.StringVar(&configFileFlag, "config", "", "From where to load declarative config")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine) // TODO: make this declarative?
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if err := run(configFileFlag); err != nil {
		setupLog.Error(err, "failed to setup the application")
		os.Exit(1)
	}
}

func run(configFileFlag string) error {

	if len(configFileFlag) == 0 {
		return errors.New("a config file is required")
	}

	cfgBytes, err := os.ReadFile(configFileFlag)
	if err != nil {
		return fmt.Errorf("unable to read config: %w", err)
	}

	cfg := Config{
		MetricsAddr:    ":9001",
		ProbeAddr:      ":9002",
		AuthorizerAddr: ":9443",
		HTTPSCertDir:   ".rebac",
	}
	err = yaml.UnmarshalStrict(cfgBytes, &cfg)
	if err != nil {
		return fmt.Errorf("unable to decode config: %w", err)
	}

	cfg.DynamicDefault()
	err = cfg.Validate()
	if err != nil {
		return fmt.Errorf("config is invalid: %w", err)
	}

	authzHost, authzPortStr, err := net.SplitHostPort(cfg.AuthorizerAddr)
	if err != nil {
		return fmt.Errorf("authorizerAddr cannot be split into host and port: %w", err)
	}
	authzPort, err := strconv.Atoi(authzPortStr)
	if err != nil {
		return fmt.Errorf("authorizerAddr port is not a number: %w", err)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: cfg.MetricsAddr},
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         cfg.EnableLeaderElection,
		LeaderElectionID:       "92980663.luxaslabs.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,

		WebhookServer: webhook.NewServer(webhook.Options{
			Host:         authzHost,
			Port:         authzPort,
			CertDir:      cfg.HTTPSCertDir,
			CertName:     "kube-rebac-authorizer.crt",
			KeyName:      "kube-rebac-authorizer.key",
			ClientCAName: "ca.crt",
		}),
	})
	if err != nil {
		return fmt.Errorf("unable to create manager: %w", err)
	}

	// Reconcile all RBAC rules in the beginning, if set
	// This might take some time
	if cfg.ReconcileRBAC != nil && *cfg.ReconcileRBAC {
		setupLog.Info("Reconciling default RBAC roles")
		err = kuberbacreconciliation.PostStartHook()(server.PostStartHookContext{
			LoopbackClientConfig: ctrl.GetConfigOrDie(),
		})
		if err != nil {
			return fmt.Errorf("unable to reconcile RBAC rules: %w", err)
		}
	}

	if cfg.Tracing != nil {
		options := []telemetry.TracerOption{
			telemetry.WithOTLPEndpoint(
				cfg.Tracing.Endpoint,
			),
			telemetry.WithAttributes(
				semconv.ServiceNameKey.String("rebac-authorizer"),
				//semconv.ServiceVersionKey.String(build.Version),
			),
			telemetry.WithSamplingRatio(cfg.Tracing.SampleRatio),
		}

		/*
			TODO: Secure comms
			if !config.Trace.OTLP.TLS.Enabled {
				options = append(options, telemetry.WithOTLPInsecure())
			}*/

		// This registers it as the global tracer provider
		// TODO: We should move this somewhere else
		// TODO: Shut down in main.go
		telemetry.MustNewTracerProvider(options...)
	}

	// TODO: support secure connection
	// TODO: Add option to run an in-memory server
	ctx := context.Background()
	cc, err := grpc.DialContext(ctx, cfg.OpenFGAClient.Address, grpc.WithTransportCredentials(insecure.NewCredentials())) // TODO: options?
	if err != nil {
		return fmt.Errorf("unable to connect to openfga server: %w", err)
	}

	storeAgnostic := openfga.NewStoreAgnosticClient(cc)

	storeClient, err := storeAgnostic.WithStore(ctx, cfg.StoreName)
	if err != nil {
		return fmt.Errorf("unable to get store %q: %w", cfg.StoreName, err)
	}

	as := rbacconversion.GetSchema()
	as.Types = append(as.Types, nodeauth.GetSchema().Types...)
	// TODO: Should we have something like that the client will refuse to write a tuple when it
	// sees its own authorization schema is "too old"?
	openfgaTupleStore, err := storeClient.WithAuthorizationSchema(ctx, as)
	if err != nil {
		return fmt.Errorf("unable to write authorization model: %w", err)
	}

	converter := &rbacconversion.GenericConverter{}

	if err = (&clusterrolesyncer.ClusterRoleReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		RBACConverter: converter,
		Zanzibar:      openfgaTupleStore,
		TypeRelation:  &as.Types[3],
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterRole")
		return err
	}

	if err = (&clusterrolebindingsyncer.ClusterRoleBindingReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		RBACConverter: converter,
		Zanzibar:      openfgaTupleStore,
		TypeRelation:  &as.Types[0],
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterRoleBinding")
		return err
	}

	if err = (&rolesyncer.RoleReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		RBACConverter: converter,
		Zanzibar:      openfgaTupleStore,
		TypeRelation:  &as.Types[2],
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Role")
		return err
	}

	if err = (&rolebindingsyncer.RoleBindingReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		RBACConverter: converter,
		Zanzibar:      openfgaTupleStore,
		TypeRelation:  &as.Types[1],
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "RoleBinding")
		return err
	}
	genericControllerGVKs := []schema.GroupVersionKind{
		v1.SchemeGroupVersion.WithKind("Node"),
		v1.SchemeGroupVersion.WithKind("Pod"),
	}
	for _, gvk := range genericControllerGVKs {

		typeName := nodeauth.GVKToTypeName(gvk)

		matchedType, err := util.MatchOne(as.Types, func(tr zanzibar.TypeRelation) bool {
			return tr.TypeName == typeName
		})
		if err != nil {
			return err
		}

		if err = (&genericsyncer.GenericTupleReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			Zanzibar:     openfgaTupleStore,
			TypeRelation: matchedType,
			GVK:          gvk,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Generic"+gvk.Kind)
			return err
		}
	}

	//+kubebuilder:scaffold:builder

	authz := &authorizer.ReBACAuthorizer{
		Checker:             openfgaTupleStore,
		AuthorizationSchema: as,
	}

	// Register the webhook server's authorization endpoint. The server will be started at mgr.Start
	mgr.GetWebhookServer().Register("/authorize", authzwebhook.NewWebhookForAuthorizer(authz))

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}
	return nil
}
