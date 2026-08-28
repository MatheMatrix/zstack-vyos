#!/bin/bash

# set all,default value
sysctl -p

VROUTER_SYSCTL_FILE=/etc/sysctl.d/99-zstack-vrouter.conf
SYSTEMD_SYSCTL=/usr/lib/systemd/systemd-sysctl
if [ -f "$VROUTER_SYSCTL_FILE" ] && [ -x "$SYSTEMD_SYSCTL" ]; then
  "$SYSTEMD_SYSCTL" "$VROUTER_SYSCTL_FILE"
fi

# set specific nic value
NIC_NAMES=$(ls /sys/class/net)
for nic in $NIC_NAMES; do
  echo 0 > /proc/sys/net/ipv6/conf/$nic/accept_dad
  echo 1 > /proc/sys/net/ipv6/conf/$nic/keep_addr_on_down
done
