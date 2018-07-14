package mappings

import (
	"fmt"
	"testing"

	"k8s.io/client-go/pkg/api/v1"
)

const (
	serviceAccountKey = "serviceAccountKey"
	scopeKey          = "scopeKey"
	namespaceKey      = "namespaceKey"
)

func TestExtractServiceAccount(t *testing.T) {
	var serviceAccountExtractionTests = []struct {
		test                  string
		annotations           map[string]string
		defaultServiceAccount string
		defaultScopes         string
		expected              string
		expectError           bool
	}{
		{
			test:        "No default, no annotation",
			annotations: map[string]string{},
			expectError: true,
		},
		{
			test:        "No default, has annotation",
			annotations: map[string]string{serviceAccountKey: "explicit-service-account"},
			expected:    "explicit-service-account",
		},
		{
			test:                  "Default present, no annotations",
			annotations:           map[string]string{},
			defaultServiceAccount: "explicit-default-service-account",
			defaultScopes:         "default-scope",
			expected:              "explicit-default-service-account",
		},
		{
			test:                  "Default present, has annotations",
			annotations:           map[string]string{serviceAccountKey: "something"},
			defaultServiceAccount: "explicit-default-service-account",
			defaultScopes:         "default-scope",
			expected:              "something",
		},
		{
			test:                  "Default present, has different annotations",
			annotations:           map[string]string{"nonMatchingAnnotation": "something"},
			defaultServiceAccount: "explicit-default-service-account",
			defaultScopes:         "default-scope",
			expected:              "explicit-default-service-account",
		},
	}
	for _, tt := range serviceAccountExtractionTests {
		t.Run(tt.test, func(t *testing.T) {
			rp := ServiceAccountMapper{}
			rp.iamServiceAccountKey = "serviceAccountKey"
			rp.defaultServiceAccount = tt.defaultServiceAccount

			pod := &v1.Pod{}
			pod.Annotations = tt.annotations

			resp, err := rp.extractServiceAccount(pod)
			if tt.expectError && err == nil {
				t.Error("Expected error however didn't recieve one")
				return
			}
			if !tt.expectError && err != nil {
				t.Errorf("Didn't expect error but recieved %s", err)
				return
			}
			if resp != tt.expected {
				t.Errorf("Response [%s] did not equal expected [%s]", resp, tt.expected)
				return
			}
		})
	}
}

func TestCheckServiceAccountForNamespace(t *testing.T) {
	var serviceAccountCheckTests = []struct {
		test                  string
		namespaceRestriction  bool
		defaultServiceAccount string
		defaultScopes         string
		namespace             string
		namespaceAnnotations  map[string]string
		serviceAccount        string
		expectedResult        bool
	}{
		{
			test:                 "No restrictions",
			namespaceRestriction: false,
			serviceAccount:       "explicit-service-account",
			namespace:            "default",
			expectedResult:       true,
		},
		{
			test:                  "Restrictions enabled, default partial",
			namespaceRestriction:  true,
			defaultServiceAccount: "default-service-account",
			defaultScopes:         "default-scope",
			serviceAccount:        "default-service-account",
			expectedResult:        true,
		},
		{
			test:                  "Restrictions enabled, default full arn",
			namespaceRestriction:  true,
			defaultServiceAccount: "default-service-account",
			defaultScopes:         "default-scope",
			serviceAccount:        "default-service-account",
			expectedResult:        true,
		},
		{
			test:                  "Restrictions enabled",
			namespaceRestriction:  true,
			defaultServiceAccount: "default-service-account",
			defaultScopes:         "default-scope",
			serviceAccount:        "explicit-service-account",
			namespace:             "default",
			namespaceAnnotations:  map[string]string{namespaceKey: "[\"explicit-service-account\"]"},
			expectedResult:        true,
		},
		{
			test:                  "Restrictions enabled, service account not in annotation",
			namespaceRestriction:  true,
			defaultServiceAccount: "default-service-account",
			defaultScopes:         "default-scope",
			serviceAccount:        "test-service-account",
			namespace:             "default",
			namespaceAnnotations:  map[string]string{namespaceKey: "[\"explicit-service-account\"]"},
			expectedResult:        false,
		},
		{
			test:                 "Restrictions enabled, no annotations",
			namespaceRestriction: true,
			serviceAccount:       "explicit-service-account",
			namespace:            "default",
			namespaceAnnotations: map[string]string{namespaceKey: ""},
			expectedResult:       false,
		},
	}

	for _, tt := range serviceAccountCheckTests {
		t.Run(tt.test, func(t *testing.T) {
			rp := NewServiceAccountMapper(
				serviceAccountKey,
				scopeKey,
				tt.defaultServiceAccount,
				tt.defaultScopes,
				tt.namespaceRestriction,
				namespaceKey,
				&storeMock{
					namespace:   tt.namespace,
					annotations: tt.namespaceAnnotations,
				},
			)

			resp := rp.checkServiceAccountForNamespace(tt.serviceAccount, tt.namespace)
			if resp != tt.expectedResult {
				t.Errorf("Expected [%t] for test but recieved [%t]", tt.expectedResult, resp)
			}
		})
	}
}

type storeMock struct {
	namespace   string
	annotations map[string]string
}

func (k *storeMock) ListPodIPs() []string {
	return nil
}
func (k *storeMock) PodByIP(string) (*v1.Pod, error) {
	return nil, nil
}
func (k *storeMock) ListNamespaces() []string {
	return nil
}
func (k *storeMock) NamespaceByName(ns string) (*v1.Namespace, error) {
	if ns == k.namespace {
		nns := &v1.Namespace{}
		nns.Name = k.namespace
		nns.Annotations = k.annotations
		return nns, nil
	}
	return nil, fmt.Errorf("Namepsace isn't present")
}
