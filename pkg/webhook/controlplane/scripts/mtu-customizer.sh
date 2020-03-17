#!/bin/bash -eu

MTU=1460
DEFAULT_NETWORK_INTERFACE=$(ip route list | grep default | grep -E  'dev (\w+)' -o | awk '{print $2}')

ip link set dev $DEFAULT_NETWORK_INTERFACE mtu 1460

if [ $? -eq 0 ]
then
  echo "Successfully set MTU to $MTU for default network interface $DEFAULT_NETWORK_INTERFACE"
else
  echo "Failed to set MTU of $MTU to default network interface $DEFAULT_NETWORK_INTERFACE"
fi