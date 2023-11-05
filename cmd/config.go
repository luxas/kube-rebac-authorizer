package main

import "fmt"

type Config struct {
	// The address the metric endpoint binds to.
	// Default: ":9001"
	MetricsAddr string `json:"metricsAddr"`
	// The address the probe endpoint binds to.
	// Default: ":9002"
	ProbeAddr string `json:"probeAddr"`

	AuthorizerAddr string `json:"authorizerAddr"`
	HTTPSCertDir   string `json:"httpsCertDir"`

	ReconcileRBAC *bool `json:"reconcileRBAC"`

	// "Enable leader election for controller manager.
	// Enabling this will ensure there is only one active controller manager.
	EnableLeaderElection bool `json:"enableLeaderElection"`

	StoreName string `json:"storeName"`

	OpenFGAClient *OpenFGAClientConfig `json:"openFGAClient"`
	// TODO: Add OpenFGAServer here in the future

	Tracing *TracingConfig `json:"tracing"`
}

func (c *Config) DynamicDefault() {
	if c.OpenFGAClient == nil {
		c.OpenFGAClient = &OpenFGAClientConfig{
			Address: "localhost:8081",
		}
	}
}

func (c *Config) Validate() error {
	// TODO: Parse the addresses
	if c.OpenFGAClient == nil || c.OpenFGAClient.Address == "" {
		return fmt.Errorf(".openFGAClient.address is required")
	}
	return nil
}

type OpenFGAClientConfig struct {
	// Address specifies the gRPC host and port to dial to, e.g. "localhost:8081"
	Address string `json:"address"`
}

type TracingConfig struct {
	// Endpoint is the OLTP gRPC host and port to dial to, e.g. "localhost:4317"
	Endpoint string `json:"endpoint"`
	// SampleRatio defines what fraction of spans to send to Endpoint. Should be in [0, 1] range.
	SampleRatio float64 `json:"sampleRatio"`
}
