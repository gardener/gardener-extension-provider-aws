// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	backupbucketcontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupbucket"
	backupentrycontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupentry"
	bastioncontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/bastion"
	controlplanecontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/controlplane"
	csimigrationcontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/csimigration"
	dnsrecordcontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/dnsrecord"
	healthcheckcontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/healthcheck"
	infrastructurecontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"
	workercontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/worker"
	controlplanewebhook "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/controlplane"
	controlplaneexposurewebhook "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/controlplaneexposure"
	shootwebhook "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/shoot"

	extensionsbackupbucketcontroller "github.com/gardener/gardener/extensions/pkg/controller/backupbucket"
	extensionsbackupentrycontroller "github.com/gardener/gardener/extensions/pkg/controller/backupentry"
	extensionsbastioncontroller "github.com/gardener/gardener/extensions/pkg/controller/bastion"
	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	extensionscontrolplanecontroller "github.com/gardener/gardener/extensions/pkg/controller/controlplane"
	extensionscsimigrationcontroller "github.com/gardener/gardener/extensions/pkg/controller/csimigration"
	extensionsdnsrecordcontroller "github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	extensionshealthcheckcontroller "github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	extensionsinfrastructurecontroller "github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	extensionsworkercontroller "github.com/gardener/gardener/extensions/pkg/controller/worker"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	extensioncontrolplanewebhook "github.com/gardener/gardener/extensions/pkg/webhook/controlplane"
	extensionshootwebhook "github.com/gardener/gardener/extensions/pkg/webhook/shoot"
	"github.com/spf13/pflag"
	"golang.org/x/time/rate"
)

const (
	// ProviderRateLimitFlag is the name of the command line flag to specify the rate limit for provider operations.
	ProviderRateLimitFlag = "provider-rate-limit"
)

// ControllerSwitchOptions are the controllercmd.SwitchOptions for the provider controllers.
func ControllerSwitchOptions() *controllercmd.SwitchOptions {
	return controllercmd.NewSwitchOptions(
		controllercmd.Switch(extensionsbackupbucketcontroller.ControllerName, backupbucketcontroller.AddToManager),
		controllercmd.Switch(extensionsbackupentrycontroller.ControllerName, backupentrycontroller.AddToManager),
		controllercmd.Switch(extensionsbastioncontroller.ControllerName, bastioncontroller.AddToManager),
		controllercmd.Switch(extensionscontrolplanecontroller.ControllerName, controlplanecontroller.AddToManager),
		controllercmd.Switch(extensionscsimigrationcontroller.ControllerName, csimigrationcontroller.AddToManager),
		controllercmd.Switch(extensionsdnsrecordcontroller.ControllerName, dnsrecordcontroller.AddToManager),
		controllercmd.Switch(extensionsinfrastructurecontroller.ControllerName, infrastructurecontroller.AddToManager),
		controllercmd.Switch(extensionsworkercontroller.ControllerName, workercontroller.AddToManager),
		controllercmd.Switch(extensionshealthcheckcontroller.ControllerName, healthcheckcontroller.AddToManager),
	)
}

// WebhookSwitchOptions are the webhookcmd.SwitchOptions for the provider webhooks.
func WebhookSwitchOptions() *webhookcmd.SwitchOptions {
	return webhookcmd.NewSwitchOptions(
		webhookcmd.Switch(extensioncontrolplanewebhook.WebhookName, controlplanewebhook.AddToManager),
		webhookcmd.Switch(extensioncontrolplanewebhook.ExposureWebhookName, controlplaneexposurewebhook.AddToManager),
		webhookcmd.Switch(extensionshootwebhook.WebhookName, shootwebhook.AddToManager),
	)
}

// DNSRecordControllerOptions are command line options that can be set for dnsrecordcontroller.Options.
type DNSRecordControllerOptions struct {
	controllercmd.ControllerOptions
	ProviderRateLimit float64

	config *DNSRecordControllerConfig
}

// AddFlags implements Flagger.AddFlags.
func (c *DNSRecordControllerOptions) AddFlags(fs *pflag.FlagSet) {
	c.ControllerOptions.AddFlags(fs)
	fs.Float64Var(&c.ProviderRateLimit, ProviderRateLimitFlag, c.ProviderRateLimit, "The rate limit for provider operations.")
}

// Complete implements Completer.Complete.
func (c *DNSRecordControllerOptions) Complete() error {
	if err := c.ControllerOptions.Complete(); err != nil {
		return err
	}
	c.config = &DNSRecordControllerConfig{
		ControllerConfig:  *c.ControllerOptions.Completed(),
		ProviderRateLimit: rate.Limit(c.ProviderRateLimit),
	}
	return nil
}

// Completed returns the completed DNSRecordControllerConfig. Only call this if `Complete` was successful.
func (c *DNSRecordControllerOptions) Completed() *DNSRecordControllerConfig {
	return c.config
}

// DNSRecordControllerConfig is a completed DNSRecord controller configuration.
type DNSRecordControllerConfig struct {
	controllercmd.ControllerConfig
	ProviderRateLimit rate.Limit
}

// Apply sets the values of this DNSRecordControllerConfig in the given controller.Options.
func (c *DNSRecordControllerConfig) Apply(opts *dnsrecordcontroller.Options) {
	c.ControllerConfig.Apply(&opts.Options)
	opts.ProviderRateLimit = c.ProviderRateLimit
}

// Options initializes empty dnsrecordcontroller.Options, applies the set values and returns it.
func (c *DNSRecordControllerConfig) Options() dnsrecordcontroller.Options {
	var opts dnsrecordcontroller.Options
	c.Apply(&opts)
	return opts
}
