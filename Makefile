IMG ?= ghcr.io/burdzwastaken/osquery-operator:latest
EVENT_BRIDGE_IMG ?= ghcr.io/burdzwastaken/osquery-k8s-event-bridge:latest

CONTAINER_TOOL ?= podman
KUBECTL ?= kubectl
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

## all: generate, lint, test, build
.PHONY: all
all: generate lint test build event-bridge-build

## fmt: format go source code
.PHONY: fmt
fmt:
	go tool golangci-lint fmt ./...

## lint: vet and lint go code
.PHONY: lint
lint:
	go vet ./...
	go tool golangci-lint run ./... -v

## test: run go tests
.PHONY: test
test: manifests generate
	KUBEBUILDER_ASSETS="$$(go tool setup-envtest use -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

## tidy: tidy go modules
.PHONY: tidy
tidy:
	go mod tidy

## generate: generate CRDs, RBAC, and DeepCopy methods
.PHONY: generate
generate: manifests deepcopy

## manifests: generate CRDs and RBAC manifests
.PHONY: manifests
manifests:
	go tool controller-gen rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

## deepcopy: generate DeepCopy methods
.PHONY: deepcopy
deepcopy:
	go tool controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."

## build: build manager binary
.PHONY: build
build:
	go build -o bin/manager cmd/main.go

## event-bridge-build: build k8s-event-bridge binary
.PHONY: event-bridge-build
event-bridge-build:
	go build -o bin/k8s-event-bridge ./cmd/k8s-event-bridge/main.go

## run: run controller from host
.PHONY: run
run: manifests generate
	go run ./cmd/main.go

## docker-build: build manager container image
.PHONY: docker-build
docker-build:
	$(CONTAINER_TOOL) build -t $(IMG) .

## docker-push: push manager container image
.PHONY: docker-push
docker-push:
	$(CONTAINER_TOOL) push $(IMG)

## event-bridge-docker-build: build k8s-event-bridge container image
.PHONY: event-bridge-docker-build
event-bridge-docker-build:
	$(CONTAINER_TOOL) build -t $(EVENT_BRIDGE_IMG) -f k8s-event-bridge.Dockerfile .

## event-bridge-docker-push: push k8s-event-bridge container image
.PHONY: event-bridge-docker-push
event-bridge-docker-push:
	$(CONTAINER_TOOL) push $(EVENT_BRIDGE_IMG)

## install: install CRDs into cluster
.PHONY: install
install: manifests
	go tool kustomize build config/crd | $(KUBECTL) apply -f -

## uninstall: uninstall CRDs from cluster
.PHONY: uninstall
uninstall: manifests
	go tool kustomize build config/crd | $(KUBECTL) delete --ignore-not-found -f -

## deploy: deploy controller to cluster
.PHONY: deploy
deploy: manifests
	cd config/manager && go tool kustomize edit set image controller=$(IMG)
	go tool kustomize build config/default | $(KUBECTL) apply -f -

## undeploy: undeploy controller from cluster
.PHONY: undeploy
undeploy:
	go tool kustomize build config/default | $(KUBECTL) delete --ignore-not-found -f -

## build-installer: generate install.yaml
.PHONY: build-installer
build-installer: manifests
	mkdir -p dist
	cd config/manager && go tool kustomize edit set image controller=$(IMG)
	go tool kustomize build config/default > dist/install.yaml

## flake: update flake.lock
.PHONY: flake
flake:
	nix flake update

CLUSTER_NAME ?= osquery-operator
CLUSTER_NODES ?= 2

## cluster-create: create a minikube cluster for local development
.PHONY: cluster-create
cluster-create:
	@minikube config set rootless true 2>/dev/null || true
	@if minikube status -p $(CLUSTER_NAME) 2>/dev/null | grep -q "Running"; then \
		echo "Cluster $(CLUSTER_NAME) already running"; \
	else \
		minikube start -p $(CLUSTER_NAME) --driver=podman --container-runtime=containerd --nodes=$(CLUSTER_NODES); \
	fi

## cluster-delete: delete the minikube cluster
.PHONY: cluster-delete
cluster-delete:
	minikube delete -p $(CLUSTER_NAME)

OSQUERY_IMG ?= osquery/osquery:5.8.2-ubuntu22.04

## cluster-load: build and load images into minikube
.PHONY: cluster-load
cluster-load: docker-build event-bridge-docker-build
	rm -f /tmp/operator.tar /tmp/event-bridge.tar /tmp/osquery.tar
	$(CONTAINER_TOOL) pull $(OSQUERY_IMG) || true
	$(CONTAINER_TOOL) save $(IMG) -o /tmp/operator.tar
	$(CONTAINER_TOOL) save $(EVENT_BRIDGE_IMG) -o /tmp/event-bridge.tar
	$(CONTAINER_TOOL) save $(OSQUERY_IMG) -o /tmp/osquery.tar
	minikube -p $(CLUSTER_NAME) image load /tmp/operator.tar
	minikube -p $(CLUSTER_NAME) image load /tmp/event-bridge.tar
	minikube -p $(CLUSTER_NAME) image load /tmp/osquery.tar
	rm -f /tmp/operator.tar /tmp/event-bridge.tar /tmp/osquery.tar

## cluster-deploy: deploy the operator to minikube cluster
.PHONY: cluster-deploy
cluster-deploy: cluster-load install deploy

## cluster-example: deploy example OsqueryAgent and packs
.PHONY: cluster-example
cluster-example:
	$(KUBECTL) apply -f examples/complete-setup.yaml
	@echo "watch with: kubectl get osqueryagents,osquerypacks,daemonsets -A"

## cluster-logs: show operator logs
.PHONY: cluster-logs
cluster-logs:
	$(KUBECTL) logs -n osquery-system -l app.kubernetes.io/name=osquery-operator -f

## cluster-status: show status of osquery resources
.PHONY: cluster-status
cluster-status:
	$(KUBECTL) get osqueryagents -A
	@echo ""
	$(KUBECTL) get osquerypacks -A
	@echo ""
	$(KUBECTL) get daemonsets -n osquery-system
	@echo ""
	$(KUBECTL) get pods -n osquery-system

## cluster-events: show osquery events
.PHONY: cluster-events
cluster-events:
	$(KUBECTL) get events -n osquery-system --sort-by='.lastTimestamp' | grep -i osquery || echo "No osquery events yet"

## cluster-test: full test cycle (create, deploy, example, status)
.PHONY: cluster-test
cluster-test: cluster-create cluster-deploy cluster-example
	@echo "waiting for pods to be ready..."
	@sleep 10
	$(MAKE) cluster-status

## cluster-clean: undeploy and clean up resources
.PHONY: cluster-clean
cluster-clean: undeploy
	$(KUBECTL) delete -f examples/complete-setup.yaml --ignore-not-found

## help: print this help message
.PHONY: help
help:
	@printf 'Usage:\n'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
