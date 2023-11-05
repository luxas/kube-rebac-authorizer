package openfga

import (
	"context"
	"math"
	"strconv"
	"time"

	"google.golang.org/grpc"
)

// VENDORED CODE

// from vendor/google.golang.org/grpc/server.go:1184
func chainUnaryInterceptors(interceptors []grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return interceptors[0](ctx, req, info, getChainUnaryHandler(interceptors, 0, info, handler))
	}
}

// from vendor/google.golang.org/grpc/server.go
func getChainUnaryHandler(interceptors []grpc.UnaryServerInterceptor, curr int, info *grpc.UnaryServerInfo, finalHandler grpc.UnaryHandler) grpc.UnaryHandler {
	if curr == len(interceptors)-1 {
		return finalHandler
	}
	return func(ctx context.Context, req any) (any, error) {
		return interceptors[curr+1](ctx, req, info, getChainUnaryHandler(interceptors, curr+1, info, finalHandler))
	}
}

// copied from openfga/cmd/run/run.go
func convertStringArrayToUintArray(stringArray []string) []uint {
	uintArray := []uint{}
	for _, val := range stringArray {
		// note that we have already validated whether the array item is non-negative integer
		valInt, err := strconv.Atoi(val)
		if err == nil {
			uintArray = append(uintArray, uint(valInt))
		}
	}
	return uintArray
}

// from openfga/cmd/run/run.go

// DatastoreConfig defines OpenFGA server configurations for datastore specific settings.
type DatastoreConfig struct {

	// Engine is the datastore engine to use (e.g. 'memory', 'postgres', 'mysql')
	Engine   string
	URI      string
	Username string
	Password string

	// MaxCacheSize is the maximum number of cache keys that the storage cache can store before evicting
	// old keys. The storage cache is used to cache query results for various static resources
	// such as type definitions.
	MaxCacheSize int

	// MaxOpenConns is the maximum number of open connections to the database.
	MaxOpenConns int

	// MaxIdleConns is the maximum number of connections to the datastore in the idle connection pool.
	MaxIdleConns int

	// ConnMaxIdleTime is the maximum amount of time a connection to the datastore may be idle.
	ConnMaxIdleTime time.Duration

	// ConnMaxLifetime is the maximum amount of time a connection to the datastore may be reused.
	ConnMaxLifetime time.Duration
}

// GRPCConfig defines OpenFGA server configurations for grpc server specific settings.
type GRPCConfig struct {
	Addr string
	TLS  *TLSConfig
}

// HTTPConfig defines OpenFGA server configurations for HTTP server specific settings.
type HTTPConfig struct {
	Enabled bool
	Addr    string
	TLS     *TLSConfig

	// UpstreamTimeout is the timeout duration for proxying HTTP requests upstream
	// to the grpc endpoint. It cannot be smaller than Config.ListObjectsDeadline.
	UpstreamTimeout time.Duration

	CORSAllowedOrigins []string
	CORSAllowedHeaders []string
}

// TLSConfig defines configuration specific to Transport Layer Security (TLS) settings.
type TLSConfig struct {
	Enabled  bool
	CertPath string `mapstructure:"cert"`
	KeyPath  string `mapstructure:"key"`
}

// AuthnConfig defines OpenFGA server configurations for authentication specific settings.
type AuthnConfig struct {

	// Method is the authentication method that should be enforced (e.g. 'none', 'preshared', 'oidc')
	Method                   string
	*AuthnOIDCConfig         `mapstructure:"oidc"`
	*AuthnPresharedKeyConfig `mapstructure:"preshared"`
}

// AuthnOIDCConfig defines configurations for the 'oidc' method of authentication.
type AuthnOIDCConfig struct {
	Issuer   string
	Audience string
}

// AuthnPresharedKeyConfig defines configurations for the 'preshared' method of authentication.
type AuthnPresharedKeyConfig struct {
	// Keys define the preshared keys to verify authn tokens against.
	Keys []string
}

// LogConfig defines OpenFGA server configurations for log specific settings. For production we
// recommend using the 'json' log format.
type LogConfig struct {
	// Format is the log format to use in the log output (e.g. 'text' or 'json')
	Format string

	// Level is the log level to use in the log output (e.g. 'none', 'debug', or 'info')
	Level string
}

type TraceConfig struct {
	Enabled     bool
	OTLP        OTLPTraceConfig `mapstructure:"otlp"`
	SampleRatio float64
	ServiceName string
}

type OTLPTraceConfig struct {
	Endpoint string
	TLS      OTLPTraceTLSConfig
}

type OTLPTraceTLSConfig struct {
	Enabled bool
}

// PlaygroundConfig defines OpenFGA server configurations for the Playground specific settings.
type PlaygroundConfig struct {
	Enabled bool
	Port    int
}

// ProfilerConfig defines server configurations specific to pprof profiling.
type ProfilerConfig struct {
	Enabled bool
	Addr    string
}

// MetricConfig defines configurations for serving custom metrics from OpenFGA.
type MetricConfig struct {
	Enabled             bool
	Addr                string
	EnableRPCHistograms bool
}

// CheckQueryCache defines configuration for caching when resolving check
type CheckQueryCache struct {
	Enabled bool
	Limit   uint32 // (in items)
	TTL     time.Duration
}

type Config struct {
	// If you change any of these settings, please update the documentation at https://github.com/openfga/openfga.dev/blob/main/docs/content/intro/setup-openfga.mdx

	// ListObjectsDeadline defines the maximum amount of time to accumulate ListObjects results
	// before the server will respond. This is to protect the server from misuse of the
	// ListObjects endpoints. It cannot be larger than HTTPConfig.UpstreamTimeout.
	ListObjectsDeadline time.Duration

	// ListObjectsMaxResults defines the maximum number of results to accumulate
	// before the non-streaming ListObjects API will respond to the client.
	// This is to protect the server from misuse of the ListObjects endpoints.
	ListObjectsMaxResults uint32

	// MaxTuplesPerWrite defines the maximum number of tuples per Write endpoint.
	MaxTuplesPerWrite int

	// MaxTypesPerAuthorizationModel defines the maximum number of type definitions per authorization model for the WriteAuthorizationModel endpoint.
	MaxTypesPerAuthorizationModel int

	// MaxConcurrentReadsForListObjects defines the maximum number of concurrent database reads allowed in ListObjects queries
	MaxConcurrentReadsForListObjects uint32

	// MaxConcurrentReadsForCheck defines the maximum number of concurrent database reads allowed in Check queries
	MaxConcurrentReadsForCheck uint32

	// ChangelogHorizonOffset is an offset in minutes from the current time. Changes that occur after this offset will not be included in the response of ReadChanges.
	ChangelogHorizonOffset int

	// Experimentals is a list of the experimental features to enable in the OpenFGA server.
	Experimentals []string

	// ResolveNodeLimit indicates how deeply nested an authorization model can be before a query errors out.
	ResolveNodeLimit uint32

	// ResolveNodeBreadthLimit indicates how many nodes on a given level can be evaluated concurrently in a query
	ResolveNodeBreadthLimit uint32

	Datastore       DatastoreConfig
	GRPC            GRPCConfig
	HTTP            HTTPConfig
	Authn           AuthnConfig
	Log             LogConfig
	Trace           TraceConfig
	Playground      PlaygroundConfig
	Profiler        ProfilerConfig
	Metrics         MetricConfig
	CheckQueryCache CheckQueryCache

	RequestDurationDatastoreQueryCountBuckets []string
}

// DefaultConfig returns the OpenFGA server default configurations.
func DefaultConfig() *Config {
	return &Config{
		MaxTuplesPerWrite:                         100,
		MaxTypesPerAuthorizationModel:             100,
		MaxConcurrentReadsForCheck:                math.MaxUint32,
		MaxConcurrentReadsForListObjects:          math.MaxUint32,
		ChangelogHorizonOffset:                    0,
		ResolveNodeLimit:                          25,
		ResolveNodeBreadthLimit:                   100,
		Experimentals:                             []string{},
		ListObjectsDeadline:                       3 * time.Second, // there is a 3-second timeout elsewhere
		ListObjectsMaxResults:                     1000,
		RequestDurationDatastoreQueryCountBuckets: []string{"50", "200"},
		Datastore: DatastoreConfig{
			Engine:       "memory",
			MaxCacheSize: 100000,
			MaxIdleConns: 10,
			MaxOpenConns: 30,
		},
		GRPC: GRPCConfig{
			Addr: "0.0.0.0:8081",
			TLS:  &TLSConfig{Enabled: false},
		},
		HTTP: HTTPConfig{
			Enabled:            true,
			Addr:               "0.0.0.0:8080",
			TLS:                &TLSConfig{Enabled: false},
			UpstreamTimeout:    5 * time.Second,
			CORSAllowedOrigins: []string{"*"},
			CORSAllowedHeaders: []string{"*"},
		},
		Authn: AuthnConfig{
			Method:                  "none",
			AuthnPresharedKeyConfig: &AuthnPresharedKeyConfig{},
			AuthnOIDCConfig:         &AuthnOIDCConfig{},
		},
		Log: LogConfig{
			Format: "text",
			Level:  "info",
		},
		Trace: TraceConfig{
			Enabled: false,
			OTLP: OTLPTraceConfig{
				Endpoint: "0.0.0.0:4317",
				TLS: OTLPTraceTLSConfig{
					Enabled: false,
				},
			},
			SampleRatio: 0.2,
			ServiceName: "openfga",
		},
		Playground: PlaygroundConfig{
			Enabled: true,
			Port:    3000,
		},
		Profiler: ProfilerConfig{
			Enabled: false,
			Addr:    ":3001",
		},
		Metrics: MetricConfig{
			Enabled:             true,
			Addr:                "0.0.0.0:2112",
			EnableRPCHistograms: false,
		},
		CheckQueryCache: CheckQueryCache{
			Enabled: false,
			Limit:   10000,
			TTL:     10 * time.Second,
		},
	}
}
