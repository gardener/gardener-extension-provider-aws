#!/bin/bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

# setup virtual GOPATH
source "$GARDENER_HACK_DIR"/vgopath-setup.sh

CODE_GEN_DIR=$(go list -m -f '{{.Dir}}' k8s.io/code-generator)
source "${CODE_GEN_DIR}/kube_codegen.sh"

rm -f $GOPATH/bin/*-gen

CURRENT_DIR=$(dirname $0)
PROJECT_ROOT="${CURRENT_DIR}"/..

kube::codegen::gen_helpers \
  --boilerplate "${GARDENER_HACK_DIR}/LICENSE_BOILERPLATE.txt" \
  "${PROJECT_ROOT}/pkg/apis/aws"

#bash "${CODE_GEN_DIR}/generate-internal-groups.sh" \
#  conversion \
#  github.com/gardener/gardener-extension-provider-aws/pkg/client \
#  github.com/gardener/gardener-extension-provider-aws/pkg/apis \
#  github.com/gardener/gardener-extension-provider-aws/pkg/apis \
#  "aws:v1alpha1" \
#  --extra-peer-dirs=github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws,github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/conversion,k8s.io/apimachinery/pkg/runtime \
#  --go-header-file "${GARDENER_HACK_DIR}/LICENSE_BOILERPLATE.txt"

kube::codegen::gen_helpers \
  --boilerplate "${GARDENER_HACK_DIR}/LICENSE_BOILERPLATE.txt" \
  "${PROJECT_ROOT}/pkg/apis/config"

#bash "${CODE_GEN_DIR}/generate-internal-groups.sh" \
#  conversion \
#  github.com/gardener/gardener-extension-provider-aws/pkg/client/componentconfig \
#  github.com/gardener/gardener-extension-provider-aws/pkg/apis \
#  github.com/gardener/gardener-extension-provider-aws/pkg/apis \
#  "config:v1alpha1" \
#  --extra-peer-dirs=github.com/gardener/gardener-extension-provider-aws/pkg/apis/config,github.com/gardener/gardener-extension-provider-aws/pkg/apis/config/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/conversion,k8s.io/apimachinery/pkg/runtime,github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1 \
#  --go-header-file "${GARDENER_HACK_DIR}/LICENSE_BOILERPLATE.txt"