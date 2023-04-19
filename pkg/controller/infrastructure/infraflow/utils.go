// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package infraflow

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	"go.uber.org/atomic"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

type zoneDependencies map[string][]flow.TaskIDer

func newZoneDependencies() zoneDependencies {
	return zoneDependencies{}
}

func (d zoneDependencies) Append(zoneName string, taskIDers ...flow.TaskIDer) {
	taskIDs := d[zoneName]
	if taskIDs == nil {
		taskIDs = []flow.TaskIDer{}
		d[zoneName] = taskIDs
	}
	d[zoneName] = append(d[zoneName], taskIDers...)
}

func (d zoneDependencies) Get(zoneName string) []flow.TaskIDer {
	return d[zoneName]
}

func diffByID[T any](desired, current []T, unique func(item T) string) (toBeDeleted, toBeCreated []T, toBeChecked []struct{ desired, current T }) {
outerDelete:
	for _, c := range current {
		cuniq := unique(c)
		for _, d := range desired {
			if cuniq == unique(d) {
				toBeChecked = append(toBeChecked, struct{ desired, current T }{
					desired: d,
					current: c,
				})
				continue outerDelete
			}
		}
		toBeDeleted = append(toBeDeleted, c)
	}
outerCreate:
	for _, d := range desired {
		duniq := unique(d)
		for _, c := range current {
			if duniq == unique(c) {
				continue outerCreate
			}
		}
		toBeCreated = append(toBeCreated, d)
	}
	return
}

func findExisting[T any](ctx context.Context, id *string, tags awsclient.Tags,
	getter func(ctx context.Context, id string) (*T, error),
	finder func(ctx context.Context, tags awsclient.Tags) ([]*T, error),
	selector ...func(item *T) bool) (*T, error) {

	if id != nil {
		found, err := getter(ctx, *id)
		if err != nil {
			return nil, err
		}
		if found != nil && (len(selector) == 0 || selector[0](found)) {
			return found, nil
		}
	}

	found, err := finder(ctx, tags)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}
	if len(selector) > 0 {
		for _, item := range found {
			if selector[0](item) {
				return item, nil
			}
		}
		return nil, nil
	}
	return found[0], nil
}

type waiter struct {
	log           logr.Logger
	start         time.Time
	period        time.Duration
	message       atomic.String
	keysAndValues []any
	done          chan struct{}
}

func informOnWaiting(log logr.Logger, period time.Duration, message string, keysAndValues ...any) *waiter {
	w := &waiter{
		log:           log,
		start:         time.Now(),
		period:        period,
		keysAndValues: keysAndValues,
		done:          make(chan struct{}),
	}
	w.message.Store(message)
	go w.run()
	return w
}

func (w *waiter) UpdateMessage(message string) {
	w.message.Store(message)
}

func (w *waiter) run() {
	ticker := time.NewTicker(w.period)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			delta := int(time.Since(w.start).Seconds())
			w.log.Info(fmt.Sprintf("%s [%ds]", w.message.Load(), delta), w.keysAndValues...)
		}
	}
}

func (w *waiter) Done(err error) {
	w.done <- struct{}{}
	if err != nil {
		w.log.Info("failed: " + err.Error())
	} else {
		w.log.Info("succeeded")
	}
}

func copyMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := map[string]string{}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
