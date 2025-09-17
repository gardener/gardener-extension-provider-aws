package utils

import "net"

// IsIPv6CIDR checks if a CIDR string represents an IPv6 network
func IsIPv6CIDR(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.IP.To4() == nil
}

// HasIPv6NodeCIDR checks if any of the node CIDRs is IPv6
func HasIPv6NodeCIDR(nodeCIDRs []string) bool {
	for _, cidr := range nodeCIDRs {
		if IsIPv6CIDR(cidr) {
			return true
		}
	}
	return false
}
