// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package dnsrecord

import (
	"time"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	"github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	"golang.org/x/time/rate"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	// DefaultAddOptions are the default AddOptions for AddToManager.
	DefaultAddOptions = AddOptions{}

	logger = log.Log.WithName("aws-dnsrecord-controller")
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
func AddToManagerWithOptions(mgr manager.Manager, opts AddOptions) error {
	logger.Info("Adding dnsrecord controller", "RateLimiterOptions", opts.RateLimiter)
	return dnsrecord.Add(mgr, dnsrecord.AddArgs{
		Actuator:          NewActuator(awsclient.NewRoute53Factory(opts.RateLimiter.Limit, opts.RateLimiter.Burst, opts.RateLimiter.WaitTimeout)),
		ControllerOptions: opts.Controller,
		Predicates:        dnsrecord.DefaultPredicates(opts.IgnoreOperationAnnotation),
		Type:              aws.DNSType,
	})
}

// AddToManager adds a controller with the default Options.
func AddToManager(mgr manager.Manager) error {
	return AddToManagerWithOptions(mgr, DefaultAddOptions)
}
