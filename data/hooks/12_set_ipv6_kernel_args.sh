#!/bin/bash

# set all,default value
sysctl -p

# set specific nic value
NIC_NAMES=$(ls /sys/class/net)
for nic in $NIC_NAMES; do
  rp_filter_path="/proc/sys/net/ipv4/conf/$nic/rp_filter"
  if [ -e "$rp_filter_path" ]; then
    echo 0 > "$rp_filter_path"
  fi
  echo 0 > /proc/sys/net/ipv6/conf/$nic/accept_dad
  echo 1 > /proc/sys/net/ipv6/conf/$nic/keep_addr_on_down
done
