// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	"go.uber.org/atomic"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// ErrorMultipleMatches is returned when multiple matches are found
var ErrorMultipleMatches = fmt.Errorf("error multiple matches")

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

// FindExisting is a generic function to find resources based on their ID or tags.
func FindExisting[T any](ctx context.Context, id *string, tags awsclient.Tags,
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

	if len(selector) == 0 {
		if len(found) > 1 {
			return nil, fmt.Errorf("%w: found matches: %v", ErrorMultipleMatches, deref(found))
		}
		return found[0], nil
	}

	var res *T
	for _, item := range found {
		if selector[0](item) {
			if res != nil {
				return nil, fmt.Errorf("%w: found matches: %v, %v", ErrorMultipleMatches, res, item)
			}
			res = item
		}
	}
	return res, nil
}

type waiter struct {
	log           logr.Logger
	start         time.Time
	period        time.Duration
	message       atomic.String
	keysAndValues []any
	done          chan struct{}
}

//nolint:unparam
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

func deref[T any](ts []*T) []T {
	if reflect.TypeOf(ts).Elem().Kind() != reflect.Pointer {
		panic("dereferenced type is not a pointer")
	}
	var res []T
	for _, t := range ts {
		if t == nil {
			continue
		}
		res = append(res, *t)
	}
	return res
}

func isIPv6(ipfamilies []gardencorev1beta1.IPFamily) bool {
	return slices.Contains(ipfamilies, gardencorev1beta1.IPFamilyIPv6)
}

func isIPv4(ipfamilies []gardencorev1beta1.IPFamily) bool {
	return slices.Contains(ipfamilies, gardencorev1beta1.IPFamilyIPv4)
}

func mmap[T any, R any](in []T, f func(t T) R) []R {
	res := make([]R, 0, len(in))
	for _, v := range in {
		res = append(res, f(v))
	}
	return res
}
