# Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

EXTENSION_PREFIX            := gardener-extension
NAME                        := provider-aws
ADMISSION_NAME              := admission-aws
REGISTRY                    := europe-docker.pkg.dev/gardener-project/public/gardener
IMAGE_PREFIX                := $(REGISTRY)/extensions
REPO_ROOT                   := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
HACK_DIR                    := $(REPO_ROOT)/hack
VERSION                     := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION           := $(VERSION)-$(shell git rev-parse HEAD)
LD_FLAGS                    := "-w $(shell $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION $(EXTENSION_PREFIX))"
LEADER_ELECTION             := false
IGNORE_OPERATION_ANNOTATION := true

WEBHOOK_CONFIG_PORT	:= 8443
WEBHOOK_CONFIG_MODE	:= url
WEBHOOK_CONFIG_URL	:= host.docker.internal:$(WEBHOOK_CONFIG_PORT)
EXTENSION_NAMESPACE	:=

WEBHOOK_PARAM := --webhook-config-url=$(WEBHOOK_CONFIG_URL)
ifeq ($(WEBHOOK_CONFIG_MODE), service)
  WEBHOOK_PARAM := --webhook-config-namespace=$(EXTENSION_NAMESPACE)
endif

REGION                 := eu-west-1
ACCESS_KEY_ID_FILE     := .kube-secrets/aws/access_key_id.secret
SECRET_ACCESS_KEY_FILE := .kube-secrets/aws/secret_access_key.secret

ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif

#########################################
# Tools                                 #
#########################################

TOOLS_DIR := hack/tools
include vendor/github.com/gardener/gardener/hack/tools.mk

#########################################
# Rules for local development scenarios #
#########################################

.PHONY: start
start:
	@LEADER_ELECTION_NAMESPACE=garden GO111MODULE=on go run \
		-mod=vendor \
		-ldflags $(LD_FLAGS) \
		./cmd/$(EXTENSION_PREFIX)-$(NAME) \
		--config-file=./example/00-componentconfig.yaml \
		--ignore-operation-annotation=$(IGNORE_OPERATION_ANNOTATION) \
		--leader-election=$(LEADER_ELECTION) \
		--webhook-config-server-host=0.0.0.0 \
		--webhook-config-server-port=$(WEBHOOK_CONFIG_PORT) \
		--webhook-config-mode=$(WEBHOOK_CONFIG_MODE) \
		--gardener-version="v1.39.0" \
		$(WEBHOOK_PARAM)

.PHONY: start-admission
start-admission:
	@LEADER_ELECTION_NAMESPACE=garden GO111MODULE=on go run \
		-mod=vendor \
		-ldflags $(LD_FLAGS) \
		./cmd/$(EXTENSION_PREFIX)-$(ADMISSION_NAME) \
		--webhook-config-server-host=0.0.0.0 \
		--webhook-config-server-port=9443 \
		--webhook-config-cert-dir=./example/admission-aws-certs

#################################################################
# Rules related to binary build, Docker image build and release #
#################################################################

.PHONY: install
install:
	@LD_FLAGS=$(LD_FLAGS) EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) \
	$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/install.sh ./...

.PHONY: docker-login
docker-login:
	@gcloud auth activate-service-account --key-file .kube-secrets/gcr/gcr-readwrite.json

.PHONY: docker-images
docker-images:
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(NAME):$(VERSION)           -t $(IMAGE_PREFIX)/$(NAME):latest           -f Dockerfile -m 6g --target $(EXTENSION_PREFIX)-$(NAME)           .
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):$(VERSION) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):latest -f Dockerfile -m 6g --target $(EXTENSION_PREFIX)-$(ADMISSION_NAME) .

#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################

.PHONY: revendor
revendor:
	@GO111MODULE=on go mod tidy
	@GO111MODULE=on go mod vendor
	@chmod +x $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/*
	@chmod +x $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/.ci/*
	@$(REPO_ROOT)/hack/update-github-templates.sh
	@ln -sf ../vendor/github.com/gardener/gardener/hack/cherry-pick-pull.sh $(HACK_DIR)/cherry-pick-pull.sh

.PHONY: clean
clean:
	@$(shell find ./example -type f -name "controller-registration.yaml" -exec rm '{}' \;)
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/clean.sh ./cmd/... ./pkg/... ./test/...

.PHONY: check-generate
check-generate:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check-generate.sh $(REPO_ROOT)

.PHONY: check
check: $(GOIMPORTS) $(GOLANGCI_LINT) 
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/... ./test/...
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check-charts.sh ./charts

.PHONY: generate
generate: $(CONTROLLER_GEN) $(GEN_CRD_API_REFERENCE_DOCS) $(HELM) $(MOCKGEN) $(YQ)
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/generate-sequential.sh ./charts/... ./cmd/... ./example/... ./pkg/...
	$(MAKE) format
	
.PHONY: format
format: $(GOIMPORTS) $(GOIMPORTSREVISER)
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/format.sh ./cmd ./pkg ./test

.PHONY: test
test:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test.sh ./cmd/... ./pkg/...

.PHONY: test-cov
test-cov:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test-cover.sh ./cmd/... ./pkg/...

.PHONY: test-clean
test-clean:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test-cover-clean.sh

.PHONY: verify
verify: check format test

.PHONY: verify-extended
verify-extended: check-generate check format test-cov test-clean

.PHONY: integration-test-infra
integration-test-infra:
	@go test -timeout=0 -mod=vendor ./test/integration/infrastructure \
		--v -ginkgo.v -ginkgo.progress \
		--kubeconfig=${KUBECONFIG} \
		--access-key-id='$(shell cat $(ACCESS_KEY_ID_FILE))' \
		--secret-access-key='$(shell cat $(SECRET_ACCESS_KEY_FILE))' \
		--region=$(REGION)

.PHONY: integration-test-bastion
integration-test-bastion:
	@go test -timeout=0 -mod=vendor ./test/integration/bastion \
		--v -ginkgo.v -ginkgo.progress \
		--kubeconfig=${KUBECONFIG} \
		--access-key-id='$(shell cat $(ACCESS_KEY_ID_FILE))' \
		--secret-access-key='$(shell cat $(SECRET_ACCESS_KEY_FILE))' \
		--region=$(REGION)

.PHONY: integration-test-dnsrecord
integration-test-dnsrecord:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test-integration.sh -timeout=0 ./test/integration/dnsrecord \
		--v -ginkgo.v -ginkgo.progress \
		--kubeconfig=${KUBECONFIG} \
		--access-key-id='$(shell cat $(ACCESS_KEY_ID_FILE))' \
		--secret-access-key='$(shell cat $(SECRET_ACCESS_KEY_FILE))'
