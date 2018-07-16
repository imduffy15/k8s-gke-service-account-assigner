[![Build Status](https://travis-ci.org/imduffy15/k8s-gke-service-account-assigner.svg?branch=master)](https://travis-ci.org/imduffy15/k8s-gke-service-account-assigner)
![GitHub tag](https://img.shields.io/github/tag/imduffy15/k8s-gke-service-account-assigner.svg?maxAge=86400)
![Docker Pulls](https://img.shields.io/docker/pulls/imduffy15/k8s-gke-service-account-assigner.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/imduffy15/k8s-gke-service-account-assigner?maxAge=86400)](https://goreportcard.com/report/github.com/imduffy15/k8s-gke-service-account-assigner)

# k8s-gke-service-account-assigner

Provides Google Service Account Tokens to containers running inside a kubernetes cluster based on annotations.

Inspired by and heavily based off [kube2iam](https://github.com/jtblin/kube2iam)

## Context

Service accounts are attached to instances and are accessible by services through the transparent
usage by the google-cloud-sdk of the Google instance metadata API. When using the google-cloud-sdk,
a call is made to the Google instance metadata API which provides temporary credentials
that are then used to make calls to the Google service.

## Problem statement

The problem is that in a multi-tenanted containers based world, multiple containers will be sharing the underlying
nodes. Given containers will share the same underlying nodes, they each get the same Google service account credentials.

## Solution

The solution is to redirect the traffic that is going to the Google instance metadata API for docker containers to a container
running on each instance, make a call to the Google IAM Credentials API to retrieve temporary credentials and return these to the caller.
Other calls will be proxied to the Google instance metadata API. This container will need to run with host networking enabled
so that it can call the Google instance metadata API itself.

## Usage

### Service accounts

It is necessary to create an service account which has the role `roles/iam.serviceAccountTokenCreator` so it get tokens for other service accounts and can assign it to each pod.

This service account should be associated to the kubernetes cluster and the kubernetes cluster should have the scope `https://www.googleapis.com/auth/cloud-platform` so that it can query the [IAM credentials API](https://cloud.google.com/iam/credentials/reference/rest/)

Additionally, its necessary to have enabled the [Google IAM Credentials API](https://console.developers.google.com/apis/api/iamcredentials.googleapis.com/overview?project=154456570117) for your project.

### k8s-gke-service-account-assigner daemonset

Run the k8s-gke-service-account-assigner container as a daemonset (so that it runs on each worker) with `hostNetwork: true`.
The k8s-gke-service-account-assigner daemon and iptables rule (see below) need to run before all other pods that would require
access to Google resources.

```yaml
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: saassigner
  labels:
    app: saassigner
spec:
  template:
    metadata:
      labels:
        name: saassigner
    spec:
      hostNetwork: true
      containers:
        - image: imduffy15/k8s-gke-service-account-assigner:latest
          name: saassigner
          args:
            - "--iptables=true"
            - "--host-ip=$(HOST_IP)"
            - "--node=$(NODE_NAME)"
            - "--default-service-account=default"
            - "--default-scopes=https://www.googleapis.com/auth/devstorage.read_write,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/trace.append"
          env:
            - name: HOST_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          ports:
            - containerPort: 8181
              hostPort: 8181
              name: http
```

### iptables

To prevent containers from directly accessing the Google instance metadata API and gaining unwanted access to Google resources,
the traffic to `169.254.169.254` must be proxied for docker containers.

```bash
iptables \
  --append PREROUTING \
  --protocol tcp \
  --destination 169.254.169.254 \
  --dport 80 \
  --in-interface eth0 \
  --jump DNAT \
  --table nat \
  --to-destination `curl http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/ip -H "Metadata-Flavor: Google"`:8181
```

This rule can be added automatically by setting `--iptables=true`, setting the `HOST_IP` environment
variable, and running the container in a privileged security context.

### kubernetes annotation

Add an `accounts.google.com/service-account` and `accounts.google.com/scopes` annotation to your pods with the service account
and scopes that you want to used for this pod.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: debug-shell
  labels:
    name: debug-shell
  annotations:
    accounts.google.com/service-account: "<PROJECT-ID>-compute@developer.gserviceaccount.com"
    accounts.google.com/scopes: "https://www.googleapis.com/auth/cloud-platform"
spec:
  restartPolicy: Never
  containers:
    - image: imduffy15/docker-gcloud
      imagePullPolicy: Always
      name: debug-shell
      tty: true
```

You can use `--default-service-account` and `--default-scopes` to set a fallback service account and scope to use when annotation is not set.

### Namespace Restrictions

By using the flag --namespace-restrictions you can enable a mode in which the roles that pods can assume is restricted
by an annotation on the pod's namespace. This annotation should be in the form of a json array.

To allow the debug-shell pod specified above to run in the default namespace your namespace would look like the following.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  annotations:
    accounts.google.com/allowed-service-accounts: |
      ["service-account"]
  name: default
```

### RBAC Setup

This is the basic RBAC setup to get k8s-gke-service-account-assigner working correctly when your cluster is using rbac. Below is the bare minimum to get k8s-gke-service-account-assigner working.

First we need to make a service account.

```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: k8s-gke-service-account-assigner
  namespace: kube-system
```

Next we need to setup roles and binding for the the process.

```yaml
---
apiVersion: v1
items:
  - apiVersion: rbac.authorization.k8s.io/v1beta1
    kind: ClusterRole
    metadata:
      name: k8s-gke-service-account-assigner
    rules:
      - apiGroups: [""]
        resources: ["namespaces","pods"]
        verbs: ["get","watch","list"]
  - apiVersion: rbac.authorization.k8s.io/v1beta1
    kind: ClusterRoleBinding
    metadata:
      name: k8s-gke-service-account-assigner
    subjects:
    - kind: ServiceAccount
      name: k8s-gke-service-account-assigner
      namespace: kube-system
    roleRef:
      kind: ClusterRole
      name: k8s-gke-service-account-assigner
      apiGroup: rbac.authorization.k8s.io
kind: List
```

You will notice this lives in the kube-system namespace to allow for easier seperation between system services and other services.

### Debug

By using the --debug flag you can enable some extra features making debugging easier:

- `/debug/store` endpoint enabled to dump knowledge of namespaces and service account association.

### Options

By default, `k8s-gke-service-account-assigner` will use the in-cluster method to connect to the kubernetes master, and use the
`accounts.google.com/service-account` and `accounts.google.com/scopes` annotations to retrieve the service
account and scopes for the container.

```bash
$ k8s-gke-service-account-assigner --help
Usage of ./k8s-gke-service-account-assigner:
      --api-server string                   Endpoint for the api server
      --api-token string                    Token to authenticate with the api server
      --app-port string                     Http port (default "8181")
      --backoff-max-elapsed-time duration   Max elapsed time for backoff when querying for role. (default 2s)
      --backoff-max-interval duration       Max interval for backoff when querying for role. (default 1s)
      --debug                               Enable debug features
      --default-scopes string               Fallback scopes to use when annotation is not set
      --default-service-account string      Fallback service account to use when annotation is not set
      --host-interface string               Host interface for proxying google compute engine metadata (default "eth0")
      --host-ip string                      IP address of host
      --iam-role-key string                 Pod annotation key used to retrieve the IAM role (default "accounts.google.com/service-account")
      --insecure                            Kubernetes server should be accessed without verifying the TLS. Testing only
      --iptables                            Add iptables rule (also requires --host-ip)
      --log-format string                   Log format (text/json) (default "text")
      --log-level string                    Log level (default "info")
      --metadata-addr string                Address for the google compute engine metadata (default "169.254.169.254")
      --namespace-key string                Namespace annotation key used to retrieve the service accounts allowed (value in annotation should be json array) (default "accounts.google.com/allowed-service-accounts")
      --namespace-restrictions              Enable namespace restrictions
      --node string                         Name of the node where k8s-gke-service-account-assigner is running
      --verbose                             Verbose
      --version                             Print the version and exits
```

## Development loop

- Create a Google Kubernetes Engine cluster
- Run skaffold dev
- Run make watch
- Create a container and exec onto it to make queries against the deployed k8s-gke-service-account-assigner instance
