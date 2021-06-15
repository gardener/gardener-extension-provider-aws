#!/bin/bash
#
# Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# SPDX-License-Identifier: Apache-2.0

set -e

SOURCE_PATH="$(dirname $0)/.."
INSTALLATION_PATH=${SOURCE_PATH}"/tmp/installation.yaml"

> ${INSTALLATION_PATH}

cat << EOF >> ${INSTALLATION_PATH}
apiVersion: landscaper.gardener.cloud/v1alpha1
kind: Installation
metadata:
  name: provider-aws
spec:
  componentDescriptor:
    ref:
      repositoryContext:
        type: ociRegistry
        baseUrl: eu.gcr.io/gardener-project/development
      componentName: github.com/gardener/gardener-extension-provider-aws
      version: ${EFFECTIVE_VERSION}

  blueprint:
    ref:
      resourceName: blueprint

  imports:
    targets:
      - name: cluster
        target: "#cluster"

  importDataMappings:
    cloudProfile:
      machineImages:
        - name: gardenlinux
          versions:
          - classification: preview
            cri:
            - containerRuntimes:
              - type: gvisor
              name: containerd
            version: 318.4.0
          - classification: supported
            cri:
            - containerRuntimes:
              - type: gvisor
              name: containerd
            version: 184.0.0
        - name: flatcar
          versions:
          - classification: preview
            version: 2605.11.0

      regions:
        - name: ap-northeast-1
          zones:
          - name: ap-northeast-1a
          - name: ap-northeast-1c
          - name: ap-northeast-1d
        - name: ap-northeast-2
          zones:
          - name: ap-northeast-2a
          - name: ap-northeast-2b
          - name: ap-northeast-2c
          - name: ap-northeast-2d

    kubernetesVersions:
      - classification: supported
        version: 1.20.6
      - classification: deprecated
        expirationDate: '2021-09-15T23:59:59Z'
        version: 1.20.5
      - classification: deprecated
        expirationDate: '2021-08-15T23:59:59Z'
        version: 1.20.4
      - classification: deprecated
        expirationDate: '2021-07-31T23:59:59Z'
        version: 1.20.2

    controllerRegistration:
      concurrentSyncs: 50
      resources:
        requests:
          cpu: 100m
          memory: 512Mi
        limits:
          cpu: 1000m
          memory: 1Gi
      vpa:
        enabled: true
        resourcePolicy:
          minAllowed:
            cpu: 50m
            memory: 256Mi
        updatePolicy:
          updateMode: "Auto"

    imageVectorOverwrite:
      images:
        - name: aws-lb-readvertiser
          repository: eu.gcr.io/sap-se-gcr-k8s-public/eu_gcr_io/gardener-project/gardener/aws-lb-readvertiser
          sourceRepository: github.com/gardener/aws-lb-readvertiser
          tag: sha256:4bbadddf273efb00babfa277885b4342d5a1f5006c857bbe2232a75748e12cff
        - name: cloud-controller-manager
          repository: eu.gcr.io/sap-se-gcr-k8s-public/k8s_gcr_io/hyperkube
          sourceRepository: github.com/kubernetes/kubernetes
          tag: sha256:12d877b29fb0d7c0cb90f4e8de8a98bb644df623be39ce7bab5420d2e21c2edc
          targetVersion: 1.15.12
        - name: cloud-controller-manager
          repository: eu.gcr.io/sap-se-gcr-k8s-public/k8s_gcr_io/hyperkube
          sourceRepository: github.com/kubernetes/kubernetes
          tag: sha256:ad97b353f1d8c37950248e1879d9ed48ce0eaeccba58d4d04f8f2a788c467ffe
          targetVersion: 1.16.15
EOF

