// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
package utils

import (
	"net"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
)

// IsIPv6CIDR checks if a CIDR string represents an IPv6 network
func IsIPv6CIDR(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.IP.To4() == nil
}

// HasIPv6NodeCIDR returns true if any node CIDR in the cluster is IPv6.
func HasIPv6NodeCIDR(cluster *extensionscontroller.Cluster) bool {
	if cluster == nil || cluster.Shoot == nil || cluster.Shoot.Status.Networking == nil {
		return false
	}
	for _, cidr := range cluster.Shoot.Status.Networking.Nodes {
		if IsIPv6CIDR(cidr) {
			return true
		}
	}
	return false
}
