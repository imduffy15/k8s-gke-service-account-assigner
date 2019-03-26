package saassigner

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/pkg/api/v1"
)

// NamespaceHandler outputs change events from K8.
type NamespaceHandler struct {
	namespaceKey string
}

func (h *NamespaceHandler) namespaceFields(ns *v1.Namespace) log.Fields {
	return log.Fields{
		"ns.name": ns.GetName(),
	}
}

// OnAdd called with a namespace is added to k8s.
func (h *NamespaceHandler) OnAdd(obj interface{}) {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		log.Errorf("Expected Namespace but OnAdd handler received %+v", obj)
		return
	}

	logger := log.WithFields(h.namespaceFields(ns))
	logger.Debug("Namespace OnAdd")

	serviceAccounts := GetNamespaceServiceAccountAnnotation(ns, h.namespaceKey)
	for _, serviceAccount := range serviceAccounts {
		logger.WithField("ns.serviceaccount", serviceAccount).Info("Discovered service account on namespace (OnAdd)")
	}
}

// OnUpdate called with a namespace is updated inside k8s.
func (h *NamespaceHandler) OnUpdate(oldObj, newObj interface{}) {
	nns, ok := newObj.(*v1.Namespace)
	if !ok {
		log.Errorf("Expected Namespace but OnUpdate handler received %+v %+v", oldObj, newObj)
		return
	}
	logger := log.WithFields(h.namespaceFields(nns))
	logger.Debug("Namespace OnUpdate")

	serviceAccounts := GetNamespaceServiceAccountAnnotation(nns, h.namespaceKey)

	for _, serviceAccount := range serviceAccounts {
		logger.WithField("ns.serviceaccount", serviceAccount).Info("Discovered service account on namespace (OnUpdate)")
	}
}

// OnDelete called with a namespace is removed from k8s.
func (h *NamespaceHandler) OnDelete(obj interface{}) {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		log.Errorf("Expected Namespace but OnDelete handler received %+v", obj)
		return
	}
	log.WithFields(h.namespaceFields(ns)).Info("Deleting namespace (OnDelete)")
}

// GetNamespaceServiceAccountAnnotation reads the "accounts.google.com/allowed-service-accounts" annotation off a namespace
// and splits them as a JSON list (["serviceaccount1", "serviceaccount2", "serviceaccount3"])
func GetNamespaceServiceAccountAnnotation(ns *v1.Namespace, namespaceKey string) []string {
	rolesString := ns.GetAnnotations()[namespaceKey]
	if rolesString != "" {
		var decoded []string
		if err := json.Unmarshal([]byte(rolesString), &decoded); err != nil {
			log.Errorf("Unable to decode roles on namespace %s ( service account annotation is '%s' ) with error: %s", ns.Name, rolesString, err)
		}
		return decoded
	}
	return nil
}

// NamespaceIndexFunc maps a namespace to it's name.
func NamespaceIndexFunc(obj interface{}) ([]string, error) {
	namespace, ok := obj.(*v1.Namespace)
	if !ok {
		return nil, fmt.Errorf("expected namespace but recieved: %+v", obj)
	}

	return []string{namespace.GetName()}, nil
}

// NewNamespaceHandler returns a new namespace handler.
func NewNamespaceHandler(namespaceKey string) *NamespaceHandler {
	return &NamespaceHandler{
		namespaceKey: namespaceKey,
	}
}
