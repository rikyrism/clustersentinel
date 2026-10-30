/*
Copyright 2026.

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

// Command manager runs the ClusterSentinel operator.
package main

import (
	"crypto/tls"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/rikyrism/clustersentinel/api/v1alpha1"
	"github.com/rikyrism/clustersentinel/internal/config"
	"github.com/rikyrism/clustersentinel/internal/controller"
	"github.com/rikyrism/clustersentinel/internal/manager"
	"github.com/rikyrism/clustersentinel/internal/version"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var (
		configPath           string
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
		secureMetrics        bool
		enableHTTP2          bool
		kubeAPIQPS           float64
		kubeAPIBurst         int
	)
	flag.StringVar(&configPath, "config", "",
		"Path to the operator configuration file (YAML). Defaults apply when empty.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"Address of the Prometheus metrics endpoint; 0 disables it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address of the /healthz and /readyz endpoints.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Use a Lease so that only one replica is active.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false,
		"Serve metrics over HTTPS with Kubernetes authn/authz (needs TokenReview and SubjectAccessReview RBAC).")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"Enable HTTP/2 for the metrics server (off by default, see CVE-2023-44487).")
	flag.Float64Var(&kubeAPIQPS, "kube-api-qps", 10, "Sustained queries per second to the Kubernetes API.")
	flag.IntVar(&kubeAPIBurst, "kube-api-burst", 20, "Burst of queries to the Kubernetes API.")
	opts := zap.Options{Development: false, TimeEncoder: zapcore.ISO8601TimeEncoder}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog.Info("Starting ClusterSentinel",
		"version", version.Version, "commit", version.Commit, "buildDate", version.BuildDate)

	cfg, err := config.Load(configPath)
	if err != nil {
		setupLog.Error(err, "Invalid configuration", "path", configPath)
		os.Exit(1)
	}
	setupLog.Info("Configuration loaded",
		"cluster", cfg.ClusterName,
		"profile", cfg.Scanner.Profile,
		"scanInterval", cfg.Scanner.ScanInterval.Duration.String(),
		"includeNamespaces", cfg.Scanner.Namespaces.Include,
		"excludeNamespaces", cfg.Scanner.Namespaces.Exclude,
		"notificationChannels", len(cfg.Notifications.Channels))

	if limit := manager.SetMemoryLimit(); limit > 0 {
		setupLog.Info("Go memory limit set from container limit", "bytes", limit)
	}
	operatorNamespace := os.Getenv("POD_NAMESPACE")
	if operatorNamespace == "" {
		operatorNamespace = "clustersentinel-system"
	}

	var tlsOpts []func(*tls.Config)
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} })
	}
	metricsOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if secureMetrics {
		metricsOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	restConfig := ctrl.GetConfigOrDie()
	restConfig.QPS = float32(kubeAPIQPS)
	restConfig.Burst = kubeAPIBurst
	restConfig.UserAgent = "clustersentinel/" + version.Version

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsOptions,
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                enableLeaderElection,
		LeaderElectionID:              "clustersentinel.security.clustersentinel.io",
		LeaderElectionReleaseOnCancel: true,
		Cache:                         manager.CacheOptions(cfg, operatorNamespace),
		Client: client.Options{
			Cache: &client.CacheOptions{DisableFor: manager.UncachedObjects()},
		},
	})
	if err != nil {
		setupLog.Error(err, "Failed to create manager")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	settings := cfg.Scanner.RuleSettings()
	setupLog.Info("Rules enabled", "rules", settings.EnabledIDs())
	if err := controller.Setup(ctx, mgr, &controller.Scanner{
		Client:                  mgr.GetClient(),
		Recorder:                controller.NewLogRecorder(),
		Namespaces:              cfg.Scanner.Namespaces,
		Settings:                settings,
		Rescan:                  cfg.Scanner.ScanInterval.Duration,
		MaxConcurrentReconciles: cfg.Scanner.MaxConcurrentReconciles,
	}); err != nil {
		setupLog.Error(err, "Failed to set up controllers")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Manager exited with an error")
		os.Exit(1)
	}
}
