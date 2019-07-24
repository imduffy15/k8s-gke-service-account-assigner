package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/cenk/backoff"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	saassigner "github.com/imduffy15/k8s-gke-service-account-assigner"
	"github.com/imduffy15/k8s-gke-service-account-assigner/iam"
	"github.com/imduffy15/k8s-gke-service-account-assigner/k8s"
	"github.com/imduffy15/k8s-gke-service-account-assigner/mappings"

	"cloud.google.com/go/compute/metadata"
)

const (
	defaultAppPort              = "8181"
	defaultCacheSyncAttempts    = 10
	defaultIAMServiceAccountKey = "accounts.google.com/service-account"
	defaultIAMScopeKey          = "accounts.google.com/scopes"
	defaultLogLevel             = "info"
	defaultLogFormat            = "text"
	defaultMaxElapsedTime       = 2 * time.Second
	defaultMaxInterval          = 1 * time.Second
	defaultMetadataAddress      = "169.254.169.254"
	defaultMetadataProxyAddress = "127.0.0.1:988"
	defaultEnableMetadataProxy  = false
	defaultNamespaceKey         = "accounts.google.com/allowed-service-accounts"
	defaultFlavorHeaderName     = "Metadata-Flavor"
	defaultFlavorHeaderValue    = "Google"
)

// Server encapsulates all of the parameters necessary for starting up
// the server. These can either be set via command line or directly.
type Server struct {
	APIServer             string
	APIToken              string
	AppPort               string
	IAMServiceAccountKey  string
	IAMScopeKey           string
	DefaultServiceAccount string
	DefaultScopes         string
	MetadataAddress       string
	MetadataProxyAddress  string
	HostInterface         string
	HostIP                string
	NodeName              string
	NamespaceKey          string
	LogLevel              string
	LogFormat             string
	AddIPTablesRule       bool
	Debug                 bool
	EnableMetadataProxy   bool
	Insecure              bool
	NamespaceRestriction  bool
	Verbose               bool
	Version               bool
	iam                   *iam.Client
	k8s                   *k8s.Client
	serviceAccountMapper  *mappings.ServiceAccountMapper
	BackoffMaxElapsedTime time.Duration
	BackoffMaxInterval    time.Duration
}

type appHandler func(*log.Entry, http.ResponseWriter, *http.Request)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	// Set "Metadata-Flavor: Google" header
	w.Header().Set(defaultFlavorHeaderName, defaultFlavorHeaderValue)
	return &responseWriter{w, http.StatusOK}
}

// ServeHTTP implements the net/http server Handler interface
// and recovers from panics.
func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{
		"req.method": r.Method,
		"req.path":   r.URL.Path,
		"req.remote": parseRemoteAddr(r.RemoteAddr),
	})
	start := time.Now()
	defer func() {
		var err error
		if rec := recover(); rec != nil {
			switch t := rec.(type) {
			case string:
				err = errors.New(t)
			case error:
				err = t
			default:
				err = errors.New("unknown error")
			}
			logger.WithField("res.status", http.StatusInternalServerError).
				Errorf("PANIC error processing request: %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}()
	rw := newResponseWriter(w)
	fn(logger, rw, r)
	if r.URL.Path != "/healthz" {
		latency := time.Since(start)
		logger.WithFields(log.Fields{"res.duration": latency.Nanoseconds(), "res.status": rw.statusCode}).
			Infof("%s %s (%d) took %d ns", r.Method, r.URL.Path, rw.statusCode, latency.Nanoseconds())
	}
}

func parseRemoteAddr(addr string) string {
	n := strings.IndexByte(addr, ':')
	if n <= 1 {
		return ""
	}
	hostname := addr[0:n]
	if net.ParseIP(hostname) == nil {
		return ""
	}
	return hostname
}

// xForwardedForStripper is identical to http.DefaultTransport except that it
// strips X-Forwarded-For headers.  It fulfills the http.RoundTripper
// interface.
type xForwardedForStripper struct{}

// RoundTrip wraps the http.DefaultTransport.RoundTrip method, and strips
// X-Forwarded-For headers, since httputil.ReverseProxy.ServeHTTP adds it but
// the GCE metadata server rejects requests with that header.
func (x xForwardedForStripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Del("X-Forwarded-For")
	return http.DefaultTransport.RoundTrip(req)
}

func (s *Server) getServiceAccountMapping(IP string) (*mappings.ServiceAccountMappingResult, error) {
	var serviceAccountMapping *mappings.ServiceAccountMappingResult
	var err error
	operation := func() error {
		serviceAccountMapping, err = s.serviceAccountMapper.GetServiceAccountMapping(IP)
		return err
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxInterval = s.BackoffMaxInterval
	expBackoff.MaxElapsedTime = s.BackoffMaxElapsedTime

	err = backoff.Retry(operation, expBackoff)
	if err != nil {
		return nil, err
	}

	return serviceAccountMapping, nil
}

// HealthResponse represents a response for the health check.
type HealthResponse struct {
	HostIP    string `json:"hostIP"`
	ProjectID string `json:"projectId"`
}

// ErrorResponse represents a response for errors.
type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// ServiceAccount represents a response for a service account.
type ServiceAccount struct {
	Aliases []string `json:"aliases"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
}

func (s *Server) healthHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {

	projectID, err := metadata.ProjectID()
	if err != nil {
		log.Errorf("Error getting project id %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	health := &HealthResponse{ProjectID: projectID, HostIP: s.HostIP}
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) debugStoreHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	log.Info("Dumping debug")
	o, err := json.Marshal(s.serviceAccountMapper.DumpDebugInfo())
	if err != nil {
		log.Errorf("Error converting debug map to json: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	write(logger, w, string(o))
}

func (s *Server) serviceAccountsHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	remoteIP := parseRemoteAddr(r.RemoteAddr)
	serviceAccountMapping, err := s.getServiceAccountMapping(remoteIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	write(logger, w, fmt.Sprintf("%s/\n%s/", serviceAccountMapping.ServiceAccount, "default"))
}

func (s *Server) redirect(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	correctedPath := fmt.Sprintf("%s/", r.URL.Path)
	w.Header().Set("Location", correctedPath)
	w.WriteHeader(http.StatusMovedPermanently)
	write(logger, w, correctedPath)
}

func (s *Server) serviceAccountTokenHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	serviceAccountMappingResult, err := s.validateServiceAccountRequest(logger, w, r)

	if err != nil {
		return
	}

	credentials, err := s.iam.ImpersonateServiceAccount(serviceAccountMappingResult)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(credentials); err != nil {
		logger.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) serviceAccountIdentityHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	serviceAccountMappingResult, err := s.validateServiceAccountRequest(logger, w, r)

	if err != nil {
		return
	}

	audience := r.URL.Query().Get("audience")
	if audience == "" {
		http.Error(w, "audience parameter required", http.StatusBadRequest)
		return
	}

	credentials, err := s.iam.GenerateIDToken(serviceAccountMappingResult, audience)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	write(logger, w, credentials)
}

func (s *Server) serviceAccountScopesHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	if serviceAccountMappingResult, err := s.validateServiceAccountRequest(logger, w, r); err == nil {
		for _, scope := range serviceAccountMappingResult.Scopes {
			write(logger, w, scope)
		}
	}
}

func (s *Server) serviceAccountAliasesHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	if _, err := s.validateServiceAccountRequest(logger, w, r); err == nil {
		write(logger, w, mux.Vars(r)["serviceAccount"])
	}
}

func (s *Server) serviceAccountEmailHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	if serviceAccountMappingResult, err := s.validateServiceAccountRequest(logger, w, r); err == nil {
		write(logger, w, serviceAccountMappingResult.ServiceAccount)
	}
}

func (s *Server) serviceAccountHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	if serviceAccountMappingResult, err := s.validateServiceAccountRequest(logger, w, r); err == nil {

		recursive := r.URL.Query().Get("recursive")

		if !strings.EqualFold(recursive, "True") {
			for _, path := range []string{"aliases", "email", "identity", "scopes", "token"} {
				write(logger, w, fmt.Sprintf("%s\n", path))
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&ServiceAccount{
				Aliases: []string{mux.Vars(r)["serviceAccount"]},
				Email:   serviceAccountMappingResult.ServiceAccount,
				Scopes:  serviceAccountMappingResult.Scopes,
			}); err != nil {
				logger.Errorf("Error sending json %+v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func (s *Server) validateServiceAccountRequest(logger *log.Entry, w http.ResponseWriter, r *http.Request) (*mappings.ServiceAccountMappingResult, error) {
	remoteIP := parseRemoteAddr(r.RemoteAddr)

	serviceAccountMapping, err := s.getServiceAccountMapping(remoteIP)
	if err != nil {
		log.Errorf("Failed to look up service account mapping for %s: %+v", remoteIP, err)

		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&ErrorResponse{
			Error:       "invalid_request",
			Description: "Service account not enabled on this instance",
		}); err != nil {
			logger.Errorf("Error sending json %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return nil, err
	}

	serviceAccountLogger := logger.WithFields(log.Fields{
		"pod.iam.serviceAccount": serviceAccountMapping.ServiceAccount,
		"ns.name":                serviceAccountMapping.Namespace,
	})

	wantedServiceAccount := mux.Vars(r)["serviceAccount"]

	if wantedServiceAccount == "default" {
		wantedServiceAccount = serviceAccountMapping.ServiceAccount
	}

	if wantedServiceAccount != serviceAccountMapping.ServiceAccount {
		serviceAccountLogger.WithField("params.iam.serviceAccount", wantedServiceAccount).
			Error("Invalid service account: does not match annotated service account")
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&ErrorResponse{
			Error:       "invalid_request",
			Description: "Service account not enabled on this instance",
		}); err != nil {
			logger.Errorf("Error sending json %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return nil, fmt.Errorf("invalid service account (%s): does not match annotated service account (%s)", wantedServiceAccount, serviceAccountMapping.ServiceAccount)
	}

	return serviceAccountMapping, nil
}

func (s *Server) reverseProxyHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	host := s.MetadataAddress
	if s.EnableMetadataProxy {
		host = s.MetadataProxyAddress
	}

	// Delete "Metadata-Flavor: Google" header to avoid duplication
	w.Header().Del(defaultFlavorHeaderName)
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: host})
	proxy.Transport = xForwardedForStripper{}
	proxy.ServeHTTP(w, r)
	logger.WithField("metadata.url", host).Debug("Proxy GCE metadata request")
}

func write(logger *log.Entry, w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(fmt.Sprintf("%+v", s))); err != nil {
		logger.Errorf("Error writing response: %+v", err)
	}
}

// Run runs the specified Server.
func (s *Server) Run(host, token, nodeName string, insecure bool) error {
	k, err := k8s.NewClient(host, token, nodeName, insecure)
	if err != nil {
		return err
	}
	s.k8s = k
	s.iam = iam.NewClient()
	s.serviceAccountMapper = mappings.NewServiceAccountMapper(s.IAMServiceAccountKey, s.IAMScopeKey, s.DefaultServiceAccount, s.DefaultScopes, s.NamespaceRestriction, s.NamespaceKey, s.k8s)
	podSynched := s.k8s.WatchForPods(saassigner.NewPodHandler(s.IAMServiceAccountKey))
	namespaceSynched := s.k8s.WatchForNamespaces(saassigner.NewNamespaceHandler(s.NamespaceKey))

	synced := false
	for i := 0; i < defaultCacheSyncAttempts && !synced; i++ {
		synced = cache.WaitForCacheSync(nil, podSynched, namespaceSynched)
	}

	if !synced {
		log.Fatalf("Attempted to wait for caches to be synced for %d however it is not done.  Giving up.", defaultCacheSyncAttempts)
	} else {
		log.Debugln("Caches have been synced.  Proceeding with server.")
	}

	r := mux.NewRouter()

	if s.Debug {
		// This is a potential security risk if enabled in some clusters, hence the flag
		r.Handle("/debug/store", appHandler(s.debugStoreHandler))
	}

	r.Handle("/computeMetadata/v1/instance/service-accounts", appHandler(s.redirect))
	r.Handle("/computeMetadata/v1/instance/service-accounts/", appHandler(s.serviceAccountsHandler))

	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount}", appHandler(s.redirect))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount}/", appHandler(s.serviceAccountHandler))

	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount}/aliases", appHandler(s.serviceAccountAliasesHandler))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount}/email", appHandler(s.serviceAccountEmailHandler))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount}/identity", appHandler(s.serviceAccountIdentityHandler))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount}/scopes", appHandler(s.serviceAccountScopesHandler))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount}/token", appHandler(s.serviceAccountTokenHandler))

	r.Handle("/healthz", appHandler(s.healthHandler))
	r.Handle("/{path:.*}", appHandler(s.reverseProxyHandler))

	log.Infof("Listening on port %s", s.AppPort)
	if err := http.ListenAndServe(":"+s.AppPort, r); err != nil {
		log.Fatalf("Error creating http server: %+v", err)
	}
	return nil
}

// NewServer will create a new Server with default values.
func NewServer() *Server {
	return &Server{
		AppPort:               defaultAppPort,
		BackoffMaxElapsedTime: defaultMaxElapsedTime,
		IAMServiceAccountKey:  defaultIAMServiceAccountKey,
		IAMScopeKey:           defaultIAMScopeKey,
		BackoffMaxInterval:    defaultMaxInterval,
		LogLevel:              defaultLogLevel,
		LogFormat:             defaultLogFormat,
		MetadataAddress:       defaultMetadataAddress,
		MetadataProxyAddress:  defaultMetadataProxyAddress,
		EnableMetadataProxy:   defaultEnableMetadataProxy,
		NamespaceKey:          defaultNamespaceKey,
	}
}
