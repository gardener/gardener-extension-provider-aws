// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
)

// DeployMachineDependencies implements genericactuator.WorkerDelegate.
func (w *WorkerDelegate) DeployMachineDependencies(_ context.Context) error {
	return nil
}

// CleanupMachineDependencies implements genericactuator.WorkerDelegate.
func (w *WorkerDelegate) CleanupMachineDependencies(_ context.Context) error {
	return nil
}

// PreReconcileHook implements genericactuator.WorkerDelegate.
func (w *WorkerDelegate) PreReconcileHook(_ context.Context) error {
	return nil
}

// PostReconcileHook implements genericactuator.WorkerDelegate.
func (w *WorkerDelegate) PostReconcileHook(_ context.Context) error {
	return nil
}

// PreDeleteHook implements genericactuator.WorkerDelegate.
func (w *WorkerDelegate) PreDeleteHook(_ context.Context) error {
	return nil
}

// PostDeleteHook implements genericactuator.WorkerDelegate.
func (w *WorkerDelegate) PostDeleteHook(_ context.Context) error {
	return nil
}
