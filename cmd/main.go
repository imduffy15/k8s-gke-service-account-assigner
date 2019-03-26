package main

import (
	"strings"

	"cloud.google.com/go/compute/metadata"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/imduffy15/k8s-gke-service-account-assigner/iptables"
	"github.com/imduffy15/k8s-gke-service-account-assigner/server"
	"github.com/imduffy15/k8s-gke-service-account-assigner/version"
)

// addFlags adds the command line flags.
func addFlags(s *server.Server, fs *pflag.FlagSet) {
	fs.StringVar(&s.APIServer, "api-server", s.APIServer, "Endpoint for the api server")
	fs.StringVar(&s.APIToken, "api-token", s.APIToken, "Token to authenticate with the api server")
	fs.StringVar(&s.AppPort, "app-port", s.AppPort, "Http port")
	fs.BoolVar(&s.Debug, "debug", s.Debug, "Enable debug features")
	fs.StringVar(&s.DefaultServiceAccount, "default-service-account", s.DefaultServiceAccount, "Fallback service account to use when annotation is not set")
	fs.StringVar(&s.IAMServiceAccountKey, "iam-role-key", s.IAMServiceAccountKey, "Pod annotation key used to retrieve the IAM role")
	fs.BoolVar(&s.Insecure, "insecure", false, "Kubernetes server should be accessed without verifying the TLS. Testing only")
	fs.StringVar(&s.MetadataAddress, "metadata-addr", s.MetadataAddress, "Address for the google compute engine metadata")
	fs.StringVar(&s.MetadataProxyAddress, "metadata-proxy-addr", s.MetadataProxyAddress, "Address for the next-hop proxy, defaults to GKE's metadata-proxy location")
	fs.BoolVar(&s.EnableMetadataProxy, "enable-metadata-proxy", s.Debug, "Send traffic to next-hop proxy")
	fs.BoolVar(&s.AddIPTablesRule, "iptables", false, "Add iptables rule (also requires --host-ip)")
	fs.StringVar(&s.HostInterface, "host-interface", "eth0", "Host interface for proxying google compute engine metadata")
	fs.BoolVar(&s.NamespaceRestriction, "namespace-restrictions", false, "Enable namespace restrictions")
	fs.StringVar(&s.NamespaceKey, "namespace-key", s.NamespaceKey, "Namespace annotation key used to retrieve the service accounts allowed (value in annotation should be json array)")
	fs.StringVar(&s.HostIP, "host-ip", s.HostIP, "IP address of host")
	fs.StringVar(&s.NodeName, "node", s.NodeName, "Name of the node where k8s-gke-service-account-assigner is running")
	fs.DurationVar(&s.BackoffMaxInterval, "backoff-max-interval", s.BackoffMaxInterval, "Max interval for backoff when querying for role.")
	fs.DurationVar(&s.BackoffMaxElapsedTime, "backoff-max-elapsed-time", s.BackoffMaxElapsedTime, "Max elapsed time for backoff when querying for role.")
	fs.StringVar(&s.LogFormat, "log-format", s.LogFormat, "Log format (text/json)")
	fs.StringVar(&s.LogLevel, "log-level", s.LogLevel, "Log level")
	fs.BoolVar(&s.Verbose, "verbose", false, "Verbose")
	fs.BoolVar(&s.Version, "version", false, "Print the version and exits")
	fs.StringVar(&s.DefaultScopes, "default-scopes", s.DefaultScopes, "Fallback scopes to use when annotation is not set")
}

func main() {
	s := server.NewServer()
	addFlags(s, pflag.CommandLine)
	pflag.Parse()

	logLevel, err := log.ParseLevel(s.LogLevel)
	if err != nil {
		log.Fatalf("%s", err)
	}

	if s.Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(logLevel)
	}

	if strings.ToLower(s.LogFormat) == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}

	if s.Version {
		version.PrintVersionAndExit()
	}

	if s.DefaultServiceAccount == "default" {
		serviceAccount, err := metadata.Get("instance/service-accounts/default/email")
		if err != nil {
			log.Fatalf("%s", err)
		}
		log.Infof("Setting the default service account to %s", serviceAccount)
		s.DefaultServiceAccount = serviceAccount
	}

	if s.AddIPTablesRule {
		log.Infof("Configuring IP tables for %s %s %s %s", s.AppPort, s.MetadataAddress, s.HostInterface, s.HostIP)
		if err := iptables.AddRule(s.AppPort, s.MetadataAddress, s.HostInterface, s.HostIP); err != nil {
			log.Fatalf("%s", err)
		}
	}

	if err := s.Run(s.APIServer, s.APIToken, s.NodeName, s.Insecure); err != nil {
		log.Fatalf("%s", err)
	}
}
