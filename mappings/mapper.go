package mappings

import (
	"fmt"
	"path/filepath"
	"strings"

	saassigner "github.com/imduffy15/k8s-gke-service-account-assigner"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/pkg/api/v1"
)

// ServiceAccountMapper handles relevant logic around associating IPs with a given service account
type ServiceAccountMapper struct {
	defaultServiceAccount string
	defaultScopes         string
	iamServiceAccountKey  string
	iamScopeKey           string
	namespaceKey          string
	namespaceRestriction  bool
	store                 store
}

type store interface {
	ListPodIPs() []string
	PodByIP(string) (*v1.Pod, error)
	ListNamespaces() []string
	NamespaceByName(string) (*v1.Namespace, error)
}

// ServiceAccountMappingResult represents the relevant information for a given mapping request
type ServiceAccountMappingResult struct {
	ServiceAccount string   `json:"service_account"`
	IP             string   `json:"ip"`
	Scopes         []string `json:"scopes"`
	Namespace      string   `json:"namespace"`
}

// GetServiceAccountMapping returns the normalized iam ServiceAccountMappingResult based on IP address
func (r *ServiceAccountMapper) GetServiceAccountMapping(IP string) (*ServiceAccountMappingResult, error) {
	pod, err := r.store.PodByIP(IP)
	// If attempting to get a Pod that maps to multiple IPs
	if err != nil {
		return nil, err
	}

	serviceAccount, err := r.extractServiceAccount(pod)
	if err != nil {
		return nil, err
	}

	scopes, err := r.extractScopes(pod)
	if err != nil {
		return nil, err
	}

	// Determine if service account is allowed to be used in pod's namespace
	if r.checkServiceAccountForNamespace(serviceAccount, pod.GetNamespace()) {
		return &ServiceAccountMappingResult{ServiceAccount: serviceAccount, Scopes: scopes, Namespace: pod.GetNamespace(), IP: IP}, nil
	}

	return nil, fmt.Errorf("Service Account requested %s not valid for namespace of pod at %s with namespace %s", serviceAccount, IP, pod.GetNamespace())
}

// extractQualifiedRoleName extracts a fully qualified ARN for a given pod,
// taking into consideration the appropriate fallback logic and defaulting
// logic along with the namespace service account restrictions
func (r *ServiceAccountMapper) extractServiceAccount(pod *v1.Pod) (string, error) {
	serviceAccount, annotationPresent := pod.GetAnnotations()[r.iamServiceAccountKey]

	if !annotationPresent && r.defaultServiceAccount == "" {
		return "", fmt.Errorf("Unable to find service account for IP %s", pod.Status.PodIP)
	}

	if !annotationPresent {
		log.Warnf("Using fallback service account for IP %s", pod.Status.PodIP)
		serviceAccount = r.defaultServiceAccount
	}

	return serviceAccount, nil
}

func (r *ServiceAccountMapper) extractScopes(pod *v1.Pod) ([]string, error) {
	scopes, annotationPresent := pod.GetAnnotations()[r.iamScopeKey]

	if !annotationPresent && r.defaultScopes == "" {
		return nil, fmt.Errorf("Unable to find scopes for IP %s", pod.Status.PodIP)
	}

	if !annotationPresent {
		log.Warnf("Using fallback scopes for IP %s", pod.Status.PodIP)
		scopes = r.defaultScopes
	}

	return strings.Split(scopes, ","), nil
}

// checkServiceAccountForNamespace checks the 'database' for a service account allowed in a namespace,
// returns true if the service account is found, otheriwse false
func (r *ServiceAccountMapper) checkServiceAccountForNamespace(serviceAccount string, namespace string) bool {
	if !r.namespaceRestriction || serviceAccount == r.defaultServiceAccount {
		return true
	}

	ns, err := r.store.NamespaceByName(namespace)
	if err != nil {
		log.Debug("Unable to find an indexed namespace of %s", namespace)
		return false
	}

	ar := saassigner.GetNamespaceServiceAccountAnnotation(ns, r.namespaceKey)
	for _, serviceAccountPattern := range ar {
		if match, err := filepath.Match(serviceAccountPattern, serviceAccount); err == nil && match {
			log.Debugf("Service account: %s matched %s on namespace:%s.", serviceAccount, serviceAccountPattern, namespace)
			return true
		}
	}
	log.Warnf("Service account: %s on namespace: %s not found.", serviceAccount, namespace)
	return false
}

// DumpDebugInfo outputs all the serviceAccounts by IP address.
func (r *ServiceAccountMapper) DumpDebugInfo() map[string]interface{} {
	output := make(map[string]interface{})
	serviceAccountsByIP := make(map[string]string)
	namespacesByIP := make(map[string]string)
	serviceAccountsByNamespace := make(map[string][]string)

	for _, ip := range r.store.ListPodIPs() {
		// When pods have `hostNetwork: true` they share an IP and we receive an error
		if pod, err := r.store.PodByIP(ip); err == nil {
			namespacesByIP[ip] = pod.Namespace
			if serviceAccount, ok := pod.GetAnnotations()[r.iamServiceAccountKey]; ok {
				serviceAccountsByIP[ip] = serviceAccount
			} else {
				serviceAccountsByIP[ip] = ""
			}
		}
	}

	for _, namespaceName := range r.store.ListNamespaces() {
		if namespace, err := r.store.NamespaceByName(namespaceName); err == nil {
			serviceAccountsByNamespace[namespace.GetName()] = saassigner.GetNamespaceServiceAccountAnnotation(namespace, r.namespaceKey)
		}
	}

	output["serviceAccountsByIP"] = serviceAccountsByIP
	output["namespaceByIP"] = namespacesByIP
	output["serviceAccountsByNamespace"] = serviceAccountsByNamespace
	return output
}

// NewServiceAccountMapper returns a new ServiceAccountMapper for use.
func NewServiceAccountMapper(serviceAccountKey string, scopeKey string, defaultServiceAccount string, defaultScopes string, namespaceRestriction bool, namespaceKey string, kubeStore store) *ServiceAccountMapper {
	return &ServiceAccountMapper{
		defaultServiceAccount: defaultServiceAccount,
		defaultScopes:         defaultScopes,
		iamServiceAccountKey:  serviceAccountKey,
		iamScopeKey:           scopeKey,
		namespaceKey:          namespaceKey,
		namespaceRestriction:  namespaceRestriction,
		store:                 kubeStore,
	}
}
