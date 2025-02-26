# SPIRE Kubernetes Workload Registrar

The SPIRE Kubernetes Workload Registrar implements a Kubernetes
ValidatingAdmissionWebhook that facilitates automatic workload registration
within Kubernetes.

## Configuration

### Command Line Configuration

The registrar has the following command line flags:

| Flag         | Description                                                      | Default                       |
| ------------ | -----------------------------------------------------------------| ----------------------------- |
| `-config`    | Path on disk to the [HCL Configuration](#hcl-configuration) file | `k8s-workload-registrar.conf` |


### HCL Configuration

The configuration file is a **required** by the registrar. It contains
[HCL](https://github.com/hashicorp/hcl) encoded configurables.

| Key                        | Type     | Required? | Description                              | Default |
| -------------------------- | ---------| ---------| ----------------------------------------- | ------- |
| `log_level`                | string   | required | Log level (one of `"panic"`,`"fatal"`,`"error"`,`"warn"`, `"warning"`,`"info"`,`"debug"`,`"trace"`) | `"info"` |
| `log_path`                 | string   | optional | Path on disk to write the log | |
| `trust_domain`             | string   | required | Trust domain of the SPIRE server | |
| `agent_socket_path`        | string   | optional | Path to the Unix domain socket of the SPIRE agent. Required if server_address is not a unix domain socket address. | |
| `server_address`           | string   | required | Address of the spire server. A local socket can be specified using unix:///path/to/socket. This is not the same as the agent socket. | |
| `server_socket_path`       | string   | optional | Path to the Unix domain socket of the SPIRE server, equivalent to specifying a server_address with a "unix://..." prefix | |
| `cluster`                  | string   | required | Logical cluster to register nodes/workloads under. Must match the SPIRE SERVER PSAT node attestor configuration. | |
| `pod_label`                | string   | optional | The pod label used for [Label Based Workload Registration](#label-based-workload-registration) | |
| `pod_annotation`           | string   | optional | The pod annotation used for [Annotation Based Workload Registration](#annotation-based-workload-registration) | |
| `mode`                     | string   | optional | How to run the registrar, either using a `"webhook"`, `"reconcile`" or `"crd"`. See [Differences](#differences-between-modes) for more details. | `"webhook"` |
| `disabled_namespaces`      | []string | optional | Comma seperated list of namespaces to disable auto SVID generation for | `"kube-system", "kube-public"` |
| `check_signature_enabled`     | boolean | optional | Used to enable signature verification | `false` |

The following configuration directives are specific to `"webhook"` mode:

| Key                        | Type    | Required? | Description                              | Default |
| -------------------------- | --------| ---------| ----------------------------------------- | ------- |
| `addr`                     | string  | required | Address to bind the HTTPS listener to | `":8443"` |
| `cert_path`                | string  | required | Path on disk to the PEM-encoded server TLS certificate | `"cert.pem"` |
| `key_path`                 | string  | required | Path on disk to the PEM-encoded server TLS key |  `"key.pem"` |
| `cacert_path`              | string  | required | Path on disk to the CA certificate used to verify the client (i.e. API server) | `"cacert.pem"` |
| `insecure_skip_client_verification`  | boolean | required | If true, skips client certificate verification (in which case `cacert_path` is ignored). See [Security Considerations](#security-considerations) for more details. | `false` |

The following configuration directives are specific to `"reconcile"` mode:

| Key                        | Type    | Required? | Description                              | Default |
| -------------------------- | --------| ---------| ----------------------------------------- | ------- |
| `leader_election`          | bool    | optional | Enable/disable leader election. Enable if you have multiple registrar replicas running. | false |
| `metrics_addr`             | string  | optional | Address to expose metrics on, use `0` to disable. | `":8080"` |
| `controller_name`          | string  | optional | Forms part of the spiffe IDs used for parent IDs | `"spire-k8s-registrar"` |
| `add_pod_dns_names`        | bool    | optional | Enable/disable adding k8s DNS names to pod SVIDs. | false |
| `cluster_dns_zone`         | string  | optional | The DNS zone used for services in the k8s cluster. | `"cluster.local"` |

For CRD configuration directives see [CRD Mode Configuration](mode-crd/README.md#configuration)

### Example

```
log_level = "debug"
trust_domain = "domain.test"
server_socket_path = "/tmp/spire-server/private/api.sock"
cluster = "production"
```

## Workload Registration
When running in webhook, reconcile, or crd mode with `pod_controller=true` entries will be automatically created for
Pods. The available workload registration modes are:

| Registration Mode | pod_label | pod_annotation | identity_template | Service Account Based |
| ----------------- | --------- | -------------- | ----------------- | --------------- |
| `webhook`   | as specified by pod_label | as specified by pod_annotation | _unavailable_ | service account |
| `reconcile` | as specified by pod_label | as specified by pod_annotation | _unavailable_ | service account |
| `crd`       | as specified by pod_label | as specified by pod_annotation | as specified by identity_template | _unavailable_ |

If using `webhook` and `reconcile` modes with [Service Account Based SPIFFE IDs](#service-account-based-workload-registration), don't specify either `pod_label` or `pod_annotation`. If you use Label Based SPIFFE IDs, specify only `pod_label`. If you use Annotation Based SPIFFE IDs, specify only `pod_annotation`.

If using `webhook` and if set `check_signature_enabled = true` is used to create new selector.

### Example

```
Entry ID         : b22e70fc-9a11-4d86-8a36-b191a3d00dfb
SPIFFE ID        : spiffe://example.org/ns/spire/sa/spire-agent
Parent ID        : spiffe://example.org/k8s-workload-registrar/example-cluster/node
Revision         : 0
TTL              : default
Selector         : k8s:ns:spire
Selector         : k8s:pod-name:spire-agent-rdb2l
Selector         : k8s:signature-verified:true
```

For `crd` mode, if neither `pod_label` nor `pod_annotation`
workload registration mode is selected,
`identity_template` is used with a default configuration:
`ns/{{.Pod.Namespace}}/sa/{{.Pod.ServiceAccount}}`


It may take several seconds for newly created SVIDs to become available to workloads.

### Federated Entry Registration

The pod annotatation `spiffe.io/federatesWith` can be used to create SPIFFE ID's that federate with other trust domains.

To specify multiple trust domains, separate them with commas.

Example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    spiffe.io/federatesWith: example.com,example.io,example.ai
  name: test
spec:
  containers:
  ...
```

### Service Account Based Workload Registration

The SPIFFE ID granted to the workload is derived from the 1) service
account or 2) a configurable pod label or 3) a configurable pod annotation.

Service account derived workload registration maps the service account into a
SPIFFE ID of the form
`spiffe://<TRUSTDOMAIN>/ns/<NAMESPACE>/sa/<SERVICEACCOUNT>`. For example, if a
pod came in with the service account `blog` in the `production` namespace, the
following registration entry would be created:

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/ns/production/sa/blog
Parent ID     : ...
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

### Label Based Workload Registration

Label based workload registration maps a pod label value into a SPIFFE ID of
the form `spiffe://<TRUSTDOMAIN>/<LABELVALUE>`. For example if the registrar
was configured with the `spire-workload` label and a pod came in with
`spire-workload=example-workload`, the following registration entry would be
created:

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/example-workload
Parent ID     : ...
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

Pods that don't contain the pod label are ignored.

### Annotation Based Workload Registration

Annotation based workload registration maps a pod annotation value into a SPIFFE ID of
the form `spiffe://<TRUSTDOMAIN>/<ANNOTATIONVALUE>`. By using this mode,
it is possible to freely set the SPIFFE ID path. For example if the registrar
was configured with the `spiffe.io/spiffe-id` annotation and a pod came in with
`spiffe.io/spiffe-id: production/example-workload`, the following registration entry would be
created:

```
Entry ID      : 200d8b19-8334-443d-9494-f65d0ad64eb5
SPIFFE ID     : spiffe://example.org/production/example-workload
Parent ID     : ...
TTL           : default
Selector      : k8s:ns:production
Selector      : k8s:pod-name:example-workload-98b6b79fd-jnv5m
```

Pods that don't contain the pod annotation are ignored.

### Identity Template Based Workload Registration

This is specific to the `crd` mode. See [Identity Template Based Workload Registration](mode-crd/README.md#identity-template-based-workload-registration) in the `crd` mode documentation.

## Deployment

The registrar can either be deployed as standalone deployment, or as a container in the SPIRE server pod.
If it is deployed standalone then it will require manual creation of an admin registration entry which will match
the registrar deployment.

If it is deployed as a container within the SPIRE server pod then it talks to SPIRE server via a Unix domain socket. It will need access to a
shared volume containing the socket file.


### Reconcile Mode Configuration

To use reconcile mode you need to create appropriate roles and bind them to the ServiceAccount you intend to run the controller as.
An example can be found in `mode-reconcile/config/role.yaml`, which you would apply with `kubectl apply -f mode-reconcile/config/role.yaml`

### CRD Mode Configuration

See [Quick Start for CRD Kubernetes Workload Registrar](mode-crd/README.md#quick-start)

### Webhook Mode Configuration
The registrar will need access to its server keypair and the CA certificate it uses to verify clients.

The following K8S objects are required to set up the validating admission controller:
* `Service` pointing to the registrar port within the spire-server container
* `ValidatingWebhookConfiguration` configuring the registrar as a validating admission controller.

Additionally, unless you disable client authentication (`insecure_skip_client_verification`), you will need:
* `Config` with a user entry for the registrar service client containing the client certificate/key the API server should use to authenticate with the registrar.
* `AdmissionConfiguration` describing where the API server can locate the file containing the `Config`. This file is passed to the API server via the `--admission-control-config-file` flag.

For convenience, a command line utility is provided to generate authentication
material and relevant Kubernetes configuration YAML.

```
$ go run generate-config.go
.... YAML configuration dump ....
```

#### Webhook mode Security Considerations

The registrar authenticates clients by default. This is a very important aspect
of the overall security of the registrar since the registrar can be used to
provide indirect access to the SPIRE server API, albeit scoped. It is *NOT*
recommended to skip client verification (via the
`insecure_skip_client_verification` configurable) unless you fully understand
the risks.

#### Migrating away from the webhook

The k8s ValidatingWebhookConfiguration will need to be removed or pods may fail admission. If you used the default
configuration this can be done with:

`kubectl validatingwebhookconfiguration delete k8s-workload-registrar-webhook`

## DNS names

Both `"reconcile"` and `"crd"` mode provide the ability to add DNS names to registration entries for pods. They
currently have different ideas about what names should be added, with `"reconcile"` adding every possible name that can
be used to access a pod (via a service or directly), and `"crd"` mode limiting itself to `<service>.<namespace>.svc`.
This functionality defaults off for `"reconcile"` mode and on for `"crd"` mode.

Warning: Some software is known to "validate" DNS and IP SANs provided in client certificates by using reverse DNS.
There is no guarantee that a client in Kubernetes will be seen to connect from an IP address with valid reverse DNS
matching one of the names generated by either of these DNS name implementation, in which case such validation will fail.
If you are intending to use X509-SVIDs to authenticate clients to such services you will need to disable adding dns names
to entries. This is known to affect etcd.

## Differences between modes

The `"webhook"` mode uses a Validating Admission Webhook to capture pod creation/deletion events at admission time. It
was the first of the registrar implementations, but suffers from the following problems:
* Race conditions between add and delete for StatefulSets will regularly lead to StatefulSets without entries;
* Unavailability of the webhook either has to block admission entirely, or you'll end up with pods with no entries;
* Spire server errors have to block admission entirely, or you'll end up with pods with no entries;
* It will not clean up left behind entries for pods deleted while the webhook/spire-server was unavailable;
* Entries are not parented to individual Nodes, all SVIDs are flooded to all agents in a cluster, which severely limits scalability.
Use of the `"webhook"` mode is thus strongly discouraged, but it remains the default for backward compatibility reasons.

The `"reconcile"` mode and `"crd"` mode both make use of reconciling controllers instead of webhooks. `"reconcile"` mode,
and `"crd"` mode with the pod_controller enabled, have similar automated workload creation functionality to webhook, but
they do not suffer from the same race conditions, are capable of recovering from (and cleaning up after) failure of the registrar,
and both also ensure that automatically created entries for Pods are limited to the appropriate Nodes to prevent SVID
flooding. When used in this way, `"reconcile"` may be slightly faster to create new entries than `"crd"` mode, and requires
less configuration.

`"crd"` mode additionally provides a namespaced SpiffeID custom resource. These are used internally by the
registrar, but may also be manually created to allow creation of arbitrary Spire Entries. If you intend to manage
SpiffeID custom resources directly then it is strongly encouraged to run the controller with the `"crd"` mode's webhook
enabled.
