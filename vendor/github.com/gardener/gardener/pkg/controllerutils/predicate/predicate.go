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

package predicate

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// IsDeleting is a predicate for objects having a deletion timestamp.
func IsDeleting() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetDeletionTimestamp() != nil
	})
}

// Not inverts the passed predicate.
func Not(p predicate.Predicate) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {
			return !p.Create(event)
		},
		UpdateFunc: func(event event.UpdateEvent) bool {
			return !p.Update(event)
		},
		GenericFunc: func(event event.GenericEvent) bool {
			return !p.Generic(event)
		},
		DeleteFunc: func(event event.DeleteEvent) bool {
			return !p.Delete(event)
		},
	}
}

// EventType is an alias for byte.
type EventType byte

const (
	// Create is a constant for an event of type 'create'.
	Create EventType = iota
	// Update is a constant for an event of type 'update'.
	Update
	// Delete is a constant for an event of type 'delete'.
	Delete
	// Generic is a constant for an event of type 'generic'.
	Generic
)

// ForEventTypes is a predicate which returns true only for the provided event types.
func ForEventTypes(events ...EventType) predicate.Predicate {
	has := func(event EventType) bool {
		for _, e := range events {
			if e == event {
				return true
			}
		}
		return false
	}

	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return has(Create) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return has(Update) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return has(Delete) },
		GenericFunc: func(e event.GenericEvent) bool { return has(Generic) },
	}
}

// EvalGeneric returns true if all predicates match for the given object.
func EvalGeneric(obj client.Object, predicates ...predicate.Predicate) bool {
	e := event.GenericEvent{Object: obj}
	for _, p := range predicates {
		if !p.Generic(e) {
			return false
		}
	}

	return true
}
