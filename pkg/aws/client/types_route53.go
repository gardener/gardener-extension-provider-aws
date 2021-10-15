// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package client

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/cache"
)

const (
	// route53RateLimiterCacheTTL is the TTL to keep route53 rate limiters in a time-based eviction cache.
	route53RateLimiterCacheTTL = 1 * time.Hour
)

// NewRoute53Factory creates a new Factory that initializes a route53 rate limiter with the given limit and burst
// when creating new clients.
func NewRoute53Factory(limit rate.Limit, burst int) Factory {
	return &route53Factory{
		limit:        limit,
		burst:        burst,
		rateLimiters: cache.NewExpiring(),
	}
}

type route53Factory struct {
	limit             rate.Limit
	burst             int
	rateLimiters      *cache.Expiring
	rateLimitersMutex sync.Mutex
}

// NewClient creates a new instance of Interface for the given AWS credentials and region.
func (f *route53Factory) NewClient(accessKeyID, secretAccessKey, region string) (Interface, error) {
	c, err := NewClient(accessKeyID, secretAccessKey, region)
	if err != nil {
		return nil, err
	}
	c.Route53RateLimiter = f.getRateLimiter(accessKeyID)
	return c, nil
}

func (f *route53Factory) getRateLimiter(accessKeyID string) *rate.Limiter {
	// cache.Expiring Get and Set methods are concurrency-safe
	// However, if f rate limiter is not present in the cache, it may happen that multiple rate limiters are created
	// at the same time for the same access key id, and the desired QPS is exceeded, so use f mutex to guard against this
	f.rateLimitersMutex.Lock()
	defer f.rateLimitersMutex.Unlock()

	// Get f rate limiter from the cache, or create f new one if not present
	var rateLimiter *rate.Limiter
	if v, ok := f.rateLimiters.Get(accessKeyID); ok {
		rateLimiter = v.(*rate.Limiter)
	} else {
		rateLimiter = rate.NewLimiter(f.limit, f.burst)
	}
	// Set should be called on every Get with cache.Expiring to refresh the TTL
	f.rateLimiters.Set(accessKeyID, rateLimiter, route53RateLimiterCacheTTL)
	return rateLimiter
}
