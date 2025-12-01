# osquery-operator

A Kubernetes operator for managing [osquery](https://osquery.io/) deployments as native CRDs

## Features

- **OsqueryAgent** - Deploy osquery as a DaemonSet with automatic config generation
- **OsqueryPack** - Define query packs as CRDs, automatically distributed to agents
- **DistributedQuery** - Run ad-hoc queries across all nodes
- **QueryResult** - Store results in-cluster as custom resources
- **OsqueryAlert** - Alert on query results with Slack & webhook support

## Quick Start

```bash
# install CRDs
make install

# deploy operator
make deploy IMG=ghcr.io/burdzwastaken/osquery-operator:latest

# apply example configuration
kubectl apply -f examples/complete-setup.yaml
```

## CRDs

### OsqueryAgent

Deploys osquery to nodes matching the selector:

```yaml
apiVersion: osquery.burdz.net/v1alpha1
kind: OsqueryAgent
metadata:
  name: default
spec:
  image: osquery/osquery:5.8.2-ubuntu22.04
  nodeSelector:
    kubernetes.io/os: linux
  tolerations:
    - operator: Exists
  packSelector:
    matchLabels:
      osquery.burdz.net/enabled: "true"
  eventBridge:
    enabled: true
    createEvents: true
    createQueryResults: true
```

### OsqueryPack

Define reusable query packs:

```yaml
apiVersion: osquery.burdz.net/v1alpha1
kind: OsqueryPack
metadata:
  name: security-baseline
  labels:
    osquery.burdz.net/enabled: "true"
spec:
  platform: linux
  queries:
    - name: listening_ports
      query: "SELECT * FROM listening_ports WHERE port NOT IN (10250, 10255);"
      interval: 60
      severity: info

    - name: setuid_binaries
      query: "SELECT * FROM suid_bin WHERE path NOT LIKE '/usr/%';"
      interval: 300
      severity: high
```

### DistributedQuery

Run ad-hoc queries across all nodes:

```yaml
apiVersion: osquery.burdz.net/v1alpha1
kind: DistributedQuery
metadata:
  name: hunt-log4shell
spec:
  query: |
    SELECT path, filename
    FROM file
    WHERE path LIKE '%log4j%.jar';
  timeout: "120s"
  ttl: "24h"
```

Check results:

```bash
kubectl get distributedquery hunt-log4shell -o yaml
# or
kubectl get queryresults -l osquery.burdz.net/distributed-query=hunt-log4shell
```

### OsqueryAlert

Alert on suspicious findings:

```yaml
apiVersion: osquery.burdz.net/v1alpha1
kind: OsqueryAlert
metadata:
  name: cryptominer-detected
  namespace: osquery-system
spec:
  querySelector:
    queryName: processes_from_tmp
  condition:
    type: rowMatch
    rowMatch:
      - field: name
        regex: "(xmrig|minerd|cryptonight)"
  severity: critical
  throttle:
    period: "15m"
    maxAlerts: 1
  notify:
    slack:
      webhookSecretRef:
        name: slack-security-webhook
        namespace: osquery-system
```

## Development

```bash
# run
make run

# test
make test

# build
make build event-bridge-build

# build images
make docker-build docker-push IMG=your-registry/osquery-operator:tag
make event-bridge-docker-build event-bridge-docker-push EVENT_BRIDGE_IMG=your-registry/osquery-k8s-event-bridge:tag

# generate manifests
make manifests generate
```

### Local Cluster Testing

```bash
# minikube cluster and deploy examples
make cluster-test

# step by step:
make cluster-create
make cluster-deploy
make cluster-example
```

## License

MIT
