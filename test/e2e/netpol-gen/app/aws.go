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
	np "github.com/gardener/gardener-extensions/test/e2e/framework/networkpolicies"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
)

// awsNetworkPolicy holds aws-specific network policy settings.
type awsNetworkPolicy struct {
	np.Agnostic

	// readvertiser is the aws-readvertiser
	readvertiser *np.SourcePod
	// metadata points to AWS metadata service.
	metadata *np.Host
}

// NewCloudAware returns aws-specific PodInfo.
func NewCloudAware() np.CloudAware {
	return &awsNetworkPolicy{
		readvertiser: &np.SourcePod{
			Pod: np.Pod{
				Name: "aws-lb-readvertiser",
				Labels: labels.Set{
					"app":                     "aws-lb-readvertiser",
					"garden.sapcloud.io/role": "controlplane",
				},
				SeedClusterConstraints: sets.NewString("aws"),
			},
			ExpectedPolicies: sets.NewString(
				"allow-to-public-networks",
				"allow-to-dns",
				"allow-to-shoot-apiserver",
				"deny-all",
			),
		},
		metadata: &np.Host{
			Description: "Metadata service",
			HostName:    "169.254.169.254",
			Port:        80,
		},
	}
}

// Sources returns list of all aws-specific sources and targets.
func (a *awsNetworkPolicy) Rules() []np.Rule {
	ag := a.Agnostic
	return []np.Rule{
		a.newSource(ag.KubeAPIServer()).AllowPod(ag.EtcdMain(), ag.EtcdEvents()).AllowHost(ag.SeedKubeAPIServer(), ag.External()).Build(),
		a.newSource(ag.EtcdMain()).AllowHost(ag.External()).Build(),
		a.newSource(ag.EtcdEvents()).AllowHost(ag.External()).Build(),
		a.newSource(ag.CloudControllerManagerNotSecured()).AllowPod(ag.KubeAPIServer()).AllowHost(ag.External()).Build(),
		a.newSource(ag.CloudControllerManagerSecured()).AllowPod(ag.KubeAPIServer()).AllowHost(ag.External()).Build(),
		a.newSource(ag.DependencyWatchdog()).AllowHost(ag.SeedKubeAPIServer(), ag.External()).Build(),
		a.newSource(ag.ElasticSearch()).Build(),
		a.newSource(ag.Grafana()).AllowPod(ag.Prometheus()).Build(),
		a.newSource(ag.Kibana()).AllowTargetPod(ag.ElasticSearch().FromPort("http")).Build(),
		a.newSource(ag.AddonManager()).AllowPod(ag.KubeAPIServer()).AllowHost(ag.SeedKubeAPIServer(), ag.External()).Build(),
		a.newSource(ag.KubeControllerManagerNotSecured()).AllowPod(ag.KubeAPIServer()).AllowHost(a.metadata, ag.External()).Build(),
		a.newSource(ag.KubeControllerManagerSecured()).AllowPod(ag.KubeAPIServer()).AllowHost(a.metadata, ag.External()).Build(),
		a.newSource(ag.KubeSchedulerNotSecured()).AllowPod(ag.KubeAPIServer()).Build(),
		a.newSource(ag.KubeSchedulerSecured()).AllowPod(ag.KubeAPIServer()).Build(),
		a.newSource(ag.KubeStateMetricsShoot()).AllowPod(ag.KubeAPIServer()).Build(),
		a.newSource(ag.KubeStateMetricsSeed()).AllowHost(ag.SeedKubeAPIServer(), ag.External()).Build(),
		a.newSource(ag.MachineControllerManager()).AllowPod(ag.KubeAPIServer()).AllowHost(ag.SeedKubeAPIServer(), ag.External()).Build(),
		a.newSource(a.readvertiser).AllowPod(ag.KubeAPIServer()).AllowHost(ag.SeedKubeAPIServer(), ag.External()).Build(),
		a.newSource(ag.Prometheus()).AllowPod(
			ag.CloudControllerManagerNotSecured(),
			ag.CloudControllerManagerSecured(),
			ag.EtcdEvents(),
			ag.EtcdMain(),
			ag.KubeAPIServer(),
			ag.KubeControllerManagerNotSecured(),
			ag.KubeControllerManagerSecured(),
			ag.KubeSchedulerNotSecured(),
			ag.KubeSchedulerSecured(),
			ag.KubeStateMetricsSeed(),
			ag.KubeStateMetricsShoot(),
			ag.MachineControllerManager(),
		).AllowTargetPod(ag.ElasticSearch().FromPort("metrics")).AllowHost(ag.SeedKubeAPIServer(), ag.External(), ag.GardenPrometheus()).Build(),
	}
}

// Sources returns a list of SourcePods of AWS.
func (a *awsNetworkPolicy) Sources() []*np.SourcePod {
	ag := a.Agnostic
	return []*np.SourcePod{
		ag.AddonManager(),
		a.readvertiser,
		ag.CloudControllerManagerNotSecured(),
		ag.CloudControllerManagerSecured(),
		ag.DependencyWatchdog(),
		ag.ElasticSearch(),
		ag.EtcdEvents(),
		ag.EtcdMain(),
		ag.Grafana(),
		ag.Kibana(),
		ag.KubeAPIServer(),
		ag.KubeControllerManagerNotSecured(),
		ag.KubeControllerManagerSecured(),
		ag.KubeSchedulerNotSecured(),
		ag.KubeSchedulerSecured(),
		ag.KubeStateMetricsSeed(),
		ag.KubeStateMetricsShoot(),
		ag.MachineControllerManager(),
		ag.Prometheus(),
	}
}

// EgressFromOtherNamespaces returns list of all aws-specific sources and targets.
func (a *awsNetworkPolicy) EgressFromOtherNamespaces(sourcePod *np.SourcePod) np.Rule {
	return np.NewSource(sourcePod).DenyPod(a.Sources()...).AllowPod(a.Agnostic.KubeAPIServer()).Build()
}

func (a *awsNetworkPolicy) newSource(sourcePod *np.SourcePod) *np.RuleBuilder {
	return np.NewSource(sourcePod).DenyPod(a.Sources()...).DenyHost(a.metadata, a.Agnostic.External(), a.Agnostic.GardenPrometheus())
}

// Provider returns AWS cloud provider.
func (a *awsNetworkPolicy) Provider() string {
	return "aws"
}
