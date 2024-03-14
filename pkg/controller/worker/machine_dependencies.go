// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
)

// DeployMachineDependencies implements genericactuator.WorkerDelegate.
func (w *workerDelegate) DeployMachineDependencies(_ context.Context) error {
	return nil
}

// CleanupMachineDependencies implements genericactuator.WorkerDelegate.
func (w *workerDelegate) CleanupMachineDependencies(_ context.Context) error {
	return nil
}

// PreReconcileHook implements genericactuator.WorkerDelegate.
func (w *workerDelegate) PreReconcileHook(_ context.Context) error {
	return nil
}

// PostReconcileHook implements genericactuator.WorkerDelegate.
func (w *workerDelegate) PostReconcileHook(_ context.Context) error {
	return nil
}

// PreDeleteHook implements genericactuator.WorkerDelegate.
func (w *workerDelegate) PreDeleteHook(_ context.Context) error {
	return nil
}

// PostDeleteHook implements genericactuator.WorkerDelegate.
func (w *workerDelegate) PostDeleteHook(_ context.Context) error {
	return nil
}
