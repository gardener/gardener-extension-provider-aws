// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package app

import (
	"context"
	"fmt"
	"os"
	"time"

	druidv1alpha1 "github.com/gardener/etcd-druid/api/v1alpha1"
	"github.com/gardener/gardener/extensions/pkg/controller"
	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	genericcontrolplaneactuator "github.com/gardener/gardener/extensions/pkg/controller/controlplane/genericactuator"
	"github.com/gardener/gardener/extensions/pkg/controller/worker"
	"github.com/gardener/gardener/extensions/pkg/util"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	machinev1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	autoscalingv1beta2 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1beta2"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	awsinstall "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awscmd "github.com/gardener/gardener-extension-provider-aws/pkg/cmd"
	awsbackupbucket "github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupbucket"
	awsbackupentry "github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupentry"
	awsbastion "github.com/gardener/gardener-extension-provider-aws/pkg/controller/bastion"
	awscontrolplane "github.com/gardener/gardener-extension-provider-aws/pkg/controller/controlplane"
	awscsimigration "github.com/gardener/gardener-extension-provider-aws/pkg/controller/csimigration"
	awsdnsrecord "github.com/gardener/gardener-extension-provider-aws/pkg/controller/dnsrecord"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/healthcheck"
	awsinfrastructure "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"
	awsworker "github.com/gardener/gardener-extension-provider-aws/pkg/controller/worker"
	awscontrolplaneexposure "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/controlplaneexposure"
)

// NewControllerManagerCommand creates a new command for running a AWS provider controller.
func NewControllerManagerCommand(ctx context.Context) *cobra.Command {
	var (
		generalOpts = &controllercmd.GeneralOptions{}
		restOpts    = &controllercmd.RESTOptions{}
		mgrOpts     = &controllercmd.ManagerOptions{
			LeaderElection:             true,
			LeaderElectionResourceLock: resourcelock.LeasesResourceLock,
			LeaderElectionID:           controllercmd.LeaderElectionNameID(aws.Name),
			LeaderElectionNamespace:    os.Getenv("LEADER_ELECTION_NAMESPACE"),
			WebhookServerPort:          443,
			WebhookCertDir:             "/tmp/gardener-extensions-cert",
		}
		configFileOpts = &awscmd.ConfigOptions{}

		// options for the backupbucket controller
		backupBucketCtrlOpts = &controllercmd.ControllerOptions{
			MaxConcurrentReconciles: 5,
		}

		// options for the backupentry controller
		backupEntryCtrlOpts = &controllercmd.ControllerOptions{
			MaxConcurrentReconciles: 5,
		}

		// options for the bastion controller
		bastionCtrlOpts = &controllercmd.ControllerOptions{
			MaxConcurrentReconciles: 5,
		}

		// options for the health care controller
		healthCheckCtrlOpts = &controllercmd.ControllerOptions{
			MaxConcurrentReconciles: 5,
		}

		// options for the controlplane controller
		controlPlaneCtrlOpts = &controllercmd.ControllerOptions{
			MaxConcurrentReconciles: 5,
		}

		// options for the csimigration controller
		csiMigrationCtrlOpts = &controllercmd.ControllerOptions{
			MaxConcurrentReconciles: 5,
		}

		// options for the dnsrecord controller
		dnsRecordCtrlOpts = &awscmd.DNSRecordControllerOptions{
			ControllerOptions: controllercmd.ControllerOptions{
				MaxConcurrentReconciles: 5,
			},
			ProviderClientQPS:         1,
			ProviderClientBurst:       5,
			ProviderClientWaitTimeout: 2 * time.Second,
		}

		// options for the infrastructure controller
		infraCtrlOpts = &controllercmd.ControllerOptions{
			MaxConcurrentReconciles: 5,
		}
		reconcileOpts = &controllercmd.ReconcilerOptions{}

		// options for the worker controller
		workerCtrlOpts = &controllercmd.ControllerOptions{
			MaxConcurrentReconciles: 5,
		}
		workerReconcileOpts = &worker.Options{
			DeployCRDs: true,
		}
		workerCtrlOptsUnprefixed = controllercmd.NewOptionAggregator(workerCtrlOpts, workerReconcileOpts)

		// options for the webhook server
		webhookServerOptions = &webhookcmd.ServerOptions{
			Namespace: os.Getenv("WEBHOOK_CONFIG_NAMESPACE"),
		}

		controllerSwitches = awscmd.ControllerSwitchOptions()
		webhookSwitches    = awscmd.WebhookSwitchOptions()
		webhookOptions     = webhookcmd.NewAddToManagerOptions(aws.Name, webhookServerOptions, webhookSwitches)

		aggOption = controllercmd.NewOptionAggregator(
			generalOpts,
			restOpts,
			mgrOpts,
			controllercmd.PrefixOption("backupbucket-", backupBucketCtrlOpts),
			controllercmd.PrefixOption("backupentry-", backupEntryCtrlOpts),
			controllercmd.PrefixOption("bastion-", bastionCtrlOpts),
			controllercmd.PrefixOption("controlplane-", controlPlaneCtrlOpts),
			controllercmd.PrefixOption("csimigration-", csiMigrationCtrlOpts),
			controllercmd.PrefixOption("dnsrecord-", dnsRecordCtrlOpts),
			controllercmd.PrefixOption("infrastructure-", infraCtrlOpts),
			controllercmd.PrefixOption("worker-", &workerCtrlOptsUnprefixed),
			controllercmd.PrefixOption("healthcheck-", healthCheckCtrlOpts),
			configFileOpts,
			controllerSwitches,
			reconcileOpts,
			webhookOptions,
		)
	)

	cmd := &cobra.Command{
		Use: fmt.Sprintf("%s-controller-manager", aws.Name),

		Run: func(cmd *cobra.Command, args []string) {
			if err := aggOption.Complete(); err != nil {
				controllercmd.LogErrAndExit(err, "Error completing options")
			}

			util.ApplyClientConnectionConfigurationToRESTConfig(configFileOpts.Completed().Config.ClientConnection, restOpts.Completed().Config)

			if workerReconcileOpts.Completed().DeployCRDs {
				if err := worker.ApplyMachineResourcesForConfig(ctx, restOpts.Completed().Config); err != nil {
					controllercmd.LogErrAndExit(err, "Error ensuring the machine CRDs")
				}
			}
			mgr, err := manager.New(restOpts.Completed().Config, mgrOpts.Completed().Options())
			if err != nil {
				controllercmd.LogErrAndExit(err, "Could not instantiate manager")
			}

			scheme := mgr.GetScheme()
			if err := controller.AddToScheme(scheme); err != nil {
				controllercmd.LogErrAndExit(err, "Could not update manager scheme")
			}
			if err := awsinstall.AddToScheme(scheme); err != nil {
				controllercmd.LogErrAndExit(err, "Could not update manager scheme")
			}
			if err := druidv1alpha1.AddToScheme(scheme); err != nil {
				controllercmd.LogErrAndExit(err, "Could not update manager scheme")
			}
			if err := autoscalingv1beta2.AddToScheme(scheme); err != nil {
				controllercmd.LogErrAndExit(err, "Could not update manager scheme")
			}
			if err := machinev1alpha1.AddToScheme(scheme); err != nil {
				controllercmd.LogErrAndExit(err, "Could not update manager scheme")
			}

			useTokenRequestor, err := controller.UseTokenRequestor(generalOpts.Completed().GardenerVersion)
			if err != nil {
				controllercmd.LogErrAndExit(err, "Could not determine whether token requestor should be used")
			}
			awsworker.DefaultAddOptions.UseTokenRequestor = useTokenRequestor

			useProjectedTokenMount, err := controller.UseServiceAccountTokenVolumeProjection(generalOpts.Completed().GardenerVersion)
			if err != nil {
				controllercmd.LogErrAndExit(err, "Could not determine whether service account token volume projection should be used")
			}
			awsworker.DefaultAddOptions.UseProjectedTokenMount = useProjectedTokenMount

			// add common meta types to schema for controller-runtime to use v1.ListOptions
			metav1.AddToGroupVersion(scheme, machinev1alpha1.SchemeGroupVersion)

			configFileOpts.Completed().ApplyETCDStorage(&awscontrolplaneexposure.DefaultAddOptions.ETCDStorage)
			configFileOpts.Completed().ApplyHealthCheckConfig(&healthcheck.DefaultAddOptions.HealthCheckConfig)
			healthCheckCtrlOpts.Completed().Apply(&healthcheck.DefaultAddOptions.Controller)
			backupBucketCtrlOpts.Completed().Apply(&awsbackupbucket.DefaultAddOptions.Controller)
			backupEntryCtrlOpts.Completed().Apply(&awsbackupentry.DefaultAddOptions.Controller)
			bastionCtrlOpts.Completed().Apply(&awsbastion.DefaultAddOptions.Controller)
			controlPlaneCtrlOpts.Completed().Apply(&awscontrolplane.DefaultAddOptions.Controller)
			csiMigrationCtrlOpts.Completed().Apply(&awscsimigration.DefaultAddOptions.Controller)
			dnsRecordCtrlOpts.Completed().Apply(&awsdnsrecord.DefaultAddOptions.Controller)
			dnsRecordCtrlOpts.Completed().ApplyRateLimiter(&awsdnsrecord.DefaultAddOptions.RateLimiter)
			infraCtrlOpts.Completed().Apply(&awsinfrastructure.DefaultAddOptions.Controller)
			reconcileOpts.Completed().Apply(&awsinfrastructure.DefaultAddOptions.IgnoreOperationAnnotation)
			reconcileOpts.Completed().Apply(&awscontrolplane.DefaultAddOptions.IgnoreOperationAnnotation)
			reconcileOpts.Completed().Apply(&awsworker.DefaultAddOptions.IgnoreOperationAnnotation)
			reconcileOpts.Completed().Apply(&awsbastion.DefaultAddOptions.IgnoreOperationAnnotation)
			reconcileOpts.Completed().Apply(&awsbackupbucket.DefaultAddOptions.IgnoreOperationAnnotation)
			reconcileOpts.Completed().Apply(&awsbackupentry.DefaultAddOptions.IgnoreOperationAnnotation)
			workerCtrlOpts.Completed().Apply(&awsworker.DefaultAddOptions.Controller)

			_, shootWebhooks, err := webhookOptions.Completed().AddToManager(ctx, mgr)
			if err != nil {
				controllercmd.LogErrAndExit(err, "Could not add webhooks to manager")
			}
			awscontrolplane.DefaultAddOptions.ShootWebhooks = shootWebhooks

			// Update shoot webhook configuration in case the webhook server port has changed.
			c, err := client.New(restOpts.Completed().Config, client.Options{})
			if err != nil {
				controllercmd.LogErrAndExit(err, "Error creating client for startup tasks")
			}
			if err := genericcontrolplaneactuator.ReconcileShootWebhooksForAllNamespaces(ctx, c, aws.Name, aws.Type, mgr.GetWebhookServer().Port, shootWebhooks); err != nil {
				controllercmd.LogErrAndExit(err, "Error ensuring shoot webhooks in all namespaces")
			}

			if err := controllerSwitches.Completed().AddToManager(mgr); err != nil {
				controllercmd.LogErrAndExit(err, "Could not add controllers to manager")
			}

			if err := mgr.Start(ctx); err != nil {
				controllercmd.LogErrAndExit(err, "Error running manager")
			}
		},
	}

	aggOption.AddFlags(cmd.Flags())

	return cmd
}
