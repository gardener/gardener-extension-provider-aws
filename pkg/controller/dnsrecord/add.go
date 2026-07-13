// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package dnsrecord

import (
	"context"
	"slices"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var (
	// DefaultAddOptions are the default AddOptions for AddToManager.
	DefaultAddOptions = AddOptions{}

	// supportedExtensionClasses are the extension classes supported by the dnsrecord controller.
	// https://github.com/gardener/gardener/blob/1cccf45631183f178378cde41aa831437b10253e/pkg/provider-local/controller/dnsrecord/add.go#L25-L30
	supportedExtensionClasses = sets.New(
		extensionsv1alpha1.ExtensionClassGarden,
		extensionsv1alpha1.ExtensionClassSeed,
		extensionsv1alpha1.ExtensionClassShoot,
	)
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
	// ExtensionClasses defines the extension classes this extension is responsible for.
	ExtensionClasses []extensionsv1alpha1.ExtensionClass
}

// AddToManagerWithOptions adds a controller with the given Options to the given manager.
// The opts.Reconciler is being set with a newly instantiated actuator.
func AddToManagerWithOptions(ctx context.Context, mgr manager.Manager, opts AddOptions) error {
	classes := slices.DeleteFunc(opts.ExtensionClasses, func(class extensionsv1alpha1.ExtensionClass) bool {
		return !supportedExtensionClasses.Has(class)
	})

	return dnsrecord.Add(mgr, dnsrecord.AddArgs{
		Actuator:          NewActuator(mgr, awsclient.NewRoute53Factory(opts.RateLimiter.Limit, opts.RateLimiter.Burst, opts.RateLimiter.WaitTimeout)),
		ControllerOptions: opts.Controller,
		Predicates:        dnsrecord.DefaultPredicates(ctx, mgr, opts.IgnoreOperationAnnotation),
		Type:              aws.DNSType,
		ExtensionClasses:  classes,
	})
}

// AddToManager adds a controller with the default Options.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	return AddToManagerWithOptions(ctx, mgr, DefaultAddOptions)
}
