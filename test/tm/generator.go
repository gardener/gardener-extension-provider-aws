// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// package contains the generators for provider specific shoot configuration
package main

import (
	"flag"
	"fmt"
	"os"
	"reflect"

	"github.com/gardener/gardener/test/testmachinery/extensions/generator"
	"github.com/go-logr/logr"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	log "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

const (
	defaultNetworkVPCCIDR      = "10.250.0.0/16"
	defaultNetworkInternalCidr = "10.250.112.0/22"
	defaultNetworkPublicCidr   = "10.250.96.0/22"
	defaultNetworkWorkerCidr   = "10.250.0.0/19"
)

var (
	cfg    *generatorConfig
	logger logr.Logger
)

type generatorConfig struct {
	networkVPCCidr                   string
	networkInternalCidr              string
	networkPublicCidr                string
	networkWorkerCidr                string
	infrastructureProviderConfigPath string
	controlplaneProviderConfigPath   string
	zone                             string
}

func addFlags() {
	cfg = &generatorConfig{}
	flag.StringVar(&cfg.zone, "zone", "", "cloudprovider zone fo the shoot")
	flag.StringVar(&cfg.infrastructureProviderConfigPath, "infrastructure-provider-config-filepath", "", "filepath to the provider specific infrastructure config")
	flag.StringVar(&cfg.controlplaneProviderConfigPath, "controlplane-provider-config-filepath", "", "filepath to the provider specific controlplane config")
	flag.StringVar(&cfg.networkVPCCidr, "network-vpc-cidr", defaultNetworkVPCCIDR, "vpc network cidr")
	flag.StringVar(&cfg.networkInternalCidr, "network-internal-cidr", defaultNetworkInternalCidr, "internal network cidr")
	flag.StringVar(&cfg.networkPublicCidr, "network-public-cidr", defaultNetworkPublicCidr, "public network cidr")
	flag.StringVar(&cfg.networkWorkerCidr, "network-worker-cidr", defaultNetworkWorkerCidr, "worker network cidr")
}

func main() {
	addFlags()
	flag.Parse()
	log.SetLogger(zap.New(zap.UseDevMode(false)))
	logger = log.Log.WithName("aws-generator")
	if err := validate(); err != nil {
		logger.Error(err, "error validating input flags")
		os.Exit(1)
	}

	infra := v1alpha1.InfrastructureConfig{
		TypeMeta: v1.TypeMeta{
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
			Kind:       reflect.TypeOf(v1alpha1.InfrastructureConfig{}).Name(),
		},
		Networks: v1alpha1.Networks{
			VPC: v1alpha1.VPC{
				CIDR: &cfg.networkVPCCidr,
			},
			Zones: []v1alpha1.Zone{
				{
					Name:     cfg.zone,
					Internal: cfg.networkInternalCidr,
					Public:   cfg.networkPublicCidr,
					Workers:  cfg.networkWorkerCidr,
				},
			},
		},
	}

	cp := v1alpha1.ControlPlaneConfig{
		TypeMeta: v1.TypeMeta{
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
			Kind:       reflect.TypeOf(v1alpha1.ControlPlaneConfig{}).Name(),
		},
	}

	if err := generator.MarshalAndWriteConfig(cfg.infrastructureProviderConfigPath, infra); err != nil {
		logger.Error(err, "unable to write infrastructure config")
		os.Exit(1)
	}
	if err := generator.MarshalAndWriteConfig(cfg.controlplaneProviderConfigPath, cp); err != nil {
		logger.Error(err, "unable to write infrastructure config")
		os.Exit(1)
	}
	logger.Info("successfully written aws provider configuration", "infra", cfg.infrastructureProviderConfigPath, "controlplane", cfg.controlplaneProviderConfigPath)
}

func validate() error {
	if err := generator.ValidateString(&cfg.infrastructureProviderConfigPath); err != nil {
		return fmt.Errorf("error validating infrastructure provider config path: %w", err)
	}
	if err := generator.ValidateString(&cfg.controlplaneProviderConfigPath); err != nil {
		return fmt.Errorf("error validating controlplane provider config path: %w", err)
	}
	if err := generator.ValidateString(&cfg.zone); err != nil {
		return fmt.Errorf("error validating zone: %w", err)
	}
	//Optional Parameters
	if err := generator.ValidateString(&cfg.networkVPCCidr); err != nil {
		logger.Info("Parameter network-vpc-cidr is not set, using default.", "value", defaultNetworkVPCCIDR)
		cfg.networkVPCCidr = defaultNetworkVPCCIDR
	}
	if err := generator.ValidateString(&cfg.networkPublicCidr); err != nil {
		logger.Info("Parameter network-public-cidr is not set, using default.", "value", defaultNetworkPublicCidr)
		cfg.networkPublicCidr = defaultNetworkPublicCidr
	}
	if err := generator.ValidateString(&cfg.networkInternalCidr); err != nil {
		logger.Info("Parameter network-internal-cidr is not set, using default.", "value", defaultNetworkInternalCidr)
		cfg.networkInternalCidr = defaultNetworkInternalCidr
	}
	if err := generator.ValidateString(&cfg.networkWorkerCidr); err != nil {
		logger.Info("Parameter network-worker-cidr is not set, using default.", "value", defaultNetworkWorkerCidr)
		cfg.networkWorkerCidr = defaultNetworkWorkerCidr
	}
	return nil
}
