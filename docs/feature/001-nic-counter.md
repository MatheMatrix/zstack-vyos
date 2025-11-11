实现虚拟机内部监控的时候，没有实现网卡监控，当时错误以为virtio在宿主机和虚拟机内部的值相同，没有必要。
因此当虚拟机使用vf网卡就没有网卡监控，因为物理机上看不到VF监控，虚拟机没有实现网卡监控。

本次实现vpc内部监控
# 数据定义
在vpcOsStatistical.go增加8个统计指标:
vrouter_if_drop_in,
vrouter_if_drop_out,
vrouter_if_error_in,
vrouter_if_error_out,
vrouter_if_packets_in,
vrouter_if_packets_out,
vrouter_if_octets_in,
vrouter_if_octets_out,

每个指标有一个label: nicName

# 数据来源

> ### cat /proc/net/dev
> Inter-|   Receive                                                |  Transmit
> face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
> lo:  125440    1615    0    0    0     0          0         0   125440    1615    0    0    0     0       0          0
> eth0: 943200466 8106934    0   36    0     0          0         0 39435320  166147    0    0    0     0       0          0
> eth3:  180414    2696    0    0    0     0          0         0   454226    5279    0    0    0     0       0          0
> eth1:  537462    6663    0    5    0     0          0         0   102924    1148    0    0    0     0       0          0
> eth2: 3519999   42153    0    0    0     0          0         0 126458034   89120    0    0    0     0       0          0
> pimreg:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
> ipsec0:       0       0    0    0    0     0          0         0      304       4    0    0    0     0       0          0
> eth4:    1556      18    0    0    0     0          0         0     4630      45    0    0    0     0       0          0

解析文件内容:
Receive bytes --> vrouter_if_octets_in
Receive packets --> vrouter_if_packets_in
Receive errs --> vrouter_if_error_in
Receive drop --> vrouter_if_drop_in
Transmit bytes --> vrouter_if_octets_out
Transmit packets --> vrouter_if_packets_out
Transmit errs --> vrouter_if_error_out
Transmit drop --> vrouter_if_drop_out

忽略网卡名称不以eth, bond开头的网卡