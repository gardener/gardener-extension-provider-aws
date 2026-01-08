// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/cache"
)

const (
	// route53RateLimiterCacheTTL is the TTL to keep route53 rate limiters in a time-based eviction cache.
	route53RateLimiterCacheTTL = 1 * time.Hour
)

// Route53RateLimiterWaitError is an error to be reported if waiting for a route53 rate limiter fails.
// This can only happen if the wait time would exceed the configured wait timeout.
type Route53RateLimiterWaitError struct {
	Cause error
}

func (e *Route53RateLimiterWaitError) Error() string {
	return fmt.Sprintf("could not wait for client-side route53 rate limiter: %+v", e.Cause)
}

// NewRoute53Factory creates a new Factory that initializes a route53 rate limiter with the given limit and burst
// when creating new clients.
func NewRoute53Factory(limit rate.Limit, burst int, waitTimeout time.Duration) Factory {
	return &route53Factory{
		limit:        limit,
		burst:        burst,
		waitTimeout:  waitTimeout,
		rateLimiters: cache.NewExpiring(),
	}
}

type route53Factory struct {
	limit             rate.Limit
	burst             int
	waitTimeout       time.Duration
	rateLimiters      *cache.Expiring
	rateLimitersMutex sync.Mutex
}

// NewClient creates a new instance of Interface for the given AWS credentials and region.
func (f *route53Factory) NewClient(authConfig AuthConfig) (Interface, error) {
	c, err := NewClient(authConfig)
	if err != nil {
		return nil, err
	}

	var rateLimiterKey string
	if authConfig.AccessKey != nil {
		rateLimiterKey = authConfig.AccessKey.ID
	} else {
		// In practice single AWS Role (the same roleARN) can be assumed by multiple Workload Identities.
		// A side effect of rate limiter using the roleARN as key is that all Workload Identities assuming the same
		// RoleARN will be throttled at the same time.
		// However, most probably on the server side(AWS STS) they would be throttled also on the roleARN
		// as this is the identity authenticated with AWS.
		rateLimiterKey = authConfig.WorkloadIdentity.RoleARN
	}

	c.Route53RateLimiter = f.getRateLimiter(rateLimiterKey)
	c.Route53RateLimiterWaitTimeout = f.waitTimeout
	return c, nil
}

func (f *route53Factory) getRateLimiter(rateLimiterKey string) *rate.Limiter {
	// cache.Expiring Get and Set methods are concurrency-safe
	// However, if f rate limiter is not present in the cache, it may happen that multiple rate limiters are created
	// at the same time for the same rate limiter key, and the desired QPS is exceeded, so use f mutex to guard against this
	f.rateLimitersMutex.Lock()
	defer f.rateLimitersMutex.Unlock()

	// Get f rate limiter from the cache, or create f new one if not present
	var rateLimiter *rate.Limiter
	if v, ok := f.rateLimiters.Get(rateLimiterKey); ok {
		rateLimiter = v.(*rate.Limiter)
	} else {
		rateLimiter = rate.NewLimiter(f.limit, f.burst)
	}
	// Set should be called on every Get with cache.Expiring to refresh the TTL
	f.rateLimiters.Set(rateLimiterKey, rateLimiter, route53RateLimiterCacheTTL)
	return rateLimiter
}
