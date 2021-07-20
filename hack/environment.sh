#!/usr/bin/env bash
#
# Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# SPDX-License-Identifier: Apache-2.0

set -e

get_cd_registry () {
  # for creating and uploading a component descriptor just insert the location to your registry e.g. eu.gcr.io/sap-se-gcr-k8s-private/cnudie/gardener/development
  registry=""

  if [ -n "$registry" ]; then
    echo $registry
  else
    info "Please insert your registry for the component descriptors in function get_cd_registry in environment.sh"
    exit 1
  fi
}

get_cd_component_name () {
  echo "github.com/gardener/gardener-extension-provider-aws"
}

get_image_registry () {
  echo "eu.gcr.io/gardener-project/gardener/extensions"
}