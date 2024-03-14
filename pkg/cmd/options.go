// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"time"

	extensionsbackupbucketcontroller "github.com/gardener/gardener/extensions/pkg/controller/backupbucket"
	extensionsbackupentrycontroller "github.com/gardener/gardener/extensions/pkg/controller/backupentry"
	extensionsbastioncontroller "github.com/gardener/gardener/extensions/pkg/controller/bastion"
	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	extensionscontrolplanecontroller "github.com/gardener/gardener/extensions/pkg/controller/controlplane"
	extensionsdnsrecordcontroller "github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	extensionshealthcheckcontroller "github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	extensionsheartbeatcontroller "github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	extensionsinfrastructurecontroller "github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	extensionsworkercontroller "github.com/gardener/gardener/extensions/pkg/controller/worker"
	extensionscloudproviderwebhook "github.com/gardener/gardener/extensions/pkg/webhook/cloudprovider"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	extensioncontrolplanewebhook "github.com/gardener/gardener/extensions/pkg/webhook/controlplane"
	extensionshootwebhook "github.com/gardener/gardener/extensions/pkg/webhook/shoot"
	"github.com/spf13/pflag"
	"golang.org/x/time/rate"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	backupbucketcontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupbucket"
	backupentrycontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupentry"
	bastioncontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/bastion"
	controlplanecontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/controlplane"
	dnsrecordcontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/dnsrecord"
	healthcheckcontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/healthcheck"
	infrastructurecontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"
	workercontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/worker"
	cloudproviderwebhook "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/cloudprovider"
	controlplanewebhook "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/controlplane"
	controlplaneexposurewebhook "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/controlplaneexposure"
	shootwebhook "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/shoot"
)

const (
	// ProviderClientQPSFlag is the name of the command line flag to specify the client QPS for provider operations.
	ProviderClientQPSFlag = "provider-client-qps"
	// ProviderClientBurstFlag is the name of the command line flag to specify the client burst for provider operations.
	ProviderClientBurstFlag = "provider-client-burst"
	// ProviderClientWaitTimeoutFlag is the name of the command line flag to specify the client wait timeout for provider operations.
	ProviderClientWaitTimeoutFlag = "provider-client-wait-timeout"
)

// ControllerSwitchOptions are the controllercmd.SwitchOptions for the provider controllers.
func ControllerSwitchOptions() *controllercmd.SwitchOptions {
	return controllercmd.NewSwitchOptions(
		controllercmd.Switch(extensionsbackupbucketcontroller.ControllerName, backupbucketcontroller.AddToManager),
		controllercmd.Switch(extensionsbackupentrycontroller.ControllerName, backupentrycontroller.AddToManager),
		controllercmd.Switch(extensionsbastioncontroller.ControllerName, bastioncontroller.AddToManager),
		controllercmd.Switch(extensionscontrolplanecontroller.ControllerName, controlplanecontroller.AddToManager),
		controllercmd.Switch(extensionsdnsrecordcontroller.ControllerName, dnsrecordcontroller.AddToManager),
		controllercmd.Switch(extensionsinfrastructurecontroller.ControllerName, infrastructurecontroller.AddToManager),
		controllercmd.Switch(extensionsworkercontroller.ControllerName, workercontroller.AddToManager),
		controllercmd.Switch(extensionshealthcheckcontroller.ControllerName, healthcheckcontroller.AddToManager),
		controllercmd.Switch(extensionsheartbeatcontroller.ControllerName, extensionsheartbeatcontroller.AddToManager),
	)
}

// WebhookSwitchOptions are the webhookcmd.SwitchOptions for the provider webhooks.
func WebhookSwitchOptions() *webhookcmd.SwitchOptions {
	return webhookcmd.NewSwitchOptions(
		webhookcmd.Switch(extensioncontrolplanewebhook.WebhookName, controlplanewebhook.AddToManager),
		webhookcmd.Switch(extensioncontrolplanewebhook.ExposureWebhookName, controlplaneexposurewebhook.AddToManager),
		webhookcmd.Switch(extensionshootwebhook.WebhookName, shootwebhook.AddToManager),
		webhookcmd.Switch(extensionscloudproviderwebhook.WebhookName, cloudproviderwebhook.AddToManager),
	)
}

// DNSRecordControllerOptions are command line options that can be set for dnsrecordcontroller.Options.
type DNSRecordControllerOptions struct {
	controllercmd.ControllerOptions
	ProviderClientQPS         float64
	ProviderClientBurst       int
	ProviderClientWaitTimeout time.Duration

	config *DNSRecordControllerConfig
}

// AddFlags implements Flagger.AddFlags.
func (c *DNSRecordControllerOptions) AddFlags(fs *pflag.FlagSet) {
	c.ControllerOptions.AddFlags(fs)
	fs.Float64Var(&c.ProviderClientQPS, ProviderClientQPSFlag, c.ProviderClientQPS, "The client QPS for provider operations.")
	fs.IntVar(&c.ProviderClientBurst, ProviderClientBurstFlag, c.ProviderClientBurst, "The client burst for provider operations.")
	fs.DurationVar(&c.ProviderClientWaitTimeout, ProviderClientWaitTimeoutFlag, c.ProviderClientWaitTimeout, "The client wait timeout for provider operations.")
}

// Complete implements Completer.Complete.
func (c *DNSRecordControllerOptions) Complete() error {
	if err := c.ControllerOptions.Complete(); err != nil {
		return err
	}
	c.config = &DNSRecordControllerConfig{
		ControllerConfig:          *c.ControllerOptions.Completed(),
		ProviderClientQPS:         rate.Limit(c.ProviderClientQPS),
		ProviderClientBurst:       c.ProviderClientBurst,
		ProviderClientWaitTimeout: c.ProviderClientWaitTimeout,
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
	ProviderClientQPS         rate.Limit
	ProviderClientBurst       int
	ProviderClientWaitTimeout time.Duration
}

// Apply sets the values of this DNSRecordControllerConfig in the given controller.Options.
func (c *DNSRecordControllerConfig) Apply(opts *controller.Options) {
	c.ControllerConfig.Apply(opts)
}

// ApplyRateLimiter sets the values of this DNSRecordControllerConfig in the given dnsrecordcontroller.RateLimiterOptions.
func (c *DNSRecordControllerConfig) ApplyRateLimiter(opts *dnsrecordcontroller.RateLimiterOptions) {
	opts.Limit = c.ProviderClientQPS
	opts.Burst = c.ProviderClientBurst
	opts.WaitTimeout = c.ProviderClientWaitTimeout
}

// Options initializes empty controller.Options, applies the set values and returns it.
func (c *DNSRecordControllerConfig) Options() controller.Options {
	var opts controller.Options
	c.Apply(&opts)
	return opts
}

// RateLimiterOptions initializes empty dnsrecordcontroller.RateLimiterOptions, applies the set values and returns it.
func (c *DNSRecordControllerConfig) RateLimiterOptions() dnsrecordcontroller.RateLimiterOptions {
	var opts dnsrecordcontroller.RateLimiterOptions
	c.ApplyRateLimiter(&opts)
	return opts
}
