// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

//go:generate mockgen -package client -destination=mocks.go github.com/gardener/gardener-extension-provider-aws/pkg/aws/client Interface,Factory,Updater

package client
