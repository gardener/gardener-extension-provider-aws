// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package dnsrecord

import (
	"context"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	"golang.org/x/time/rate"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var (
	// DefaultAddOptions are the default AddOptions for AddToManager.
	DefaultAddOptions = AddOptions{}
)

// RateLimiterOptions are the options for provider rate limiters.
type RateLimiterOptions struct {
	// Limit is the rate limit for provider operations.
	Limit rate.Limit
	// Burst is the rate limiter burst for provider operations.
	Burst int
	// WaitTimeout is the timeout for rate limiter waits.
	WaitTimeout time.Duration
}

// AddOptions are options to apply when adding the AWS dnsrecord controller to the manager.
type AddOptions struct {
	// Controller are the controller.Options.
	Controller controller.Options
	// RateLimiter are the RateLimiterOptions.
	RateLimiter RateLimiterOptions
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
}

// AddToManagerWithOptions adds a controller with the given Options to the given manager.
// The opts.Reconciler is being set with a newly instantiated actuator.
func AddToManagerWithOptions(ctx context.Context, mgr manager.Manager, opts AddOptions) error {
	return dnsrecord.Add(ctx, mgr, dnsrecord.AddArgs{
		Actuator:          NewActuator(mgr, awsclient.NewRoute53Factory(opts.RateLimiter.Limit, opts.RateLimiter.Burst, opts.RateLimiter.WaitTimeout)),
		ControllerOptions: opts.Controller,
		Predicates:        dnsrecord.DefaultPredicates(ctx, mgr, opts.IgnoreOperationAnnotation),
		Type:              aws.DNSType,
	})
}

// AddToManager adds a controller with the default Options.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	return AddToManagerWithOptions(ctx, mgr, DefaultAddOptions)
}
