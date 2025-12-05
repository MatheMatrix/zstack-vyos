
1. 通过读取文件: /proc/net/nf_conntrack 获取流量session流量统计:
1.1 icmp的流量格式：
> ipv4     2 icmp     1 8 src=10.1.2.197 dst=192.168.100.1 type=8 code=0 id=63489 packets=88 bytes=7392 src=192.168.100.1 dst=192.168.100.147 type=0 code=0 id=63489 packets=20 bytes=1680 mark=0 zone=0 use=2
> ipv4     2 icmp     1 27 src=192.168.100.254 dst=192.168.100.147 type=8 code=0 id=368 packets=14 bytes=1176 src=10.1.2.197 dst=192.168.100.254 type=0 code=0 id=368 packets=14 bytes=1176 mark=0 zone=0 use=2

1.2  tcp流量格式
> ipv4     2 tcp      6 20 TIME_WAIT src=192.168.100.254 dst=192.168.100.147 sport=59792 dport=22 packets=17 bytes=3217 src=10.1.2.197 dst=192.168.100.254 sport=22 dport=59792 packets=17 bytes=2798 [ASSURED] mark=0 zone=0 use=2
> ipv4     2 tcp      6 117 TIME_WAIT src=10.1.2.197 dst=192.168.100.1 sport=39276 dport=22 packets=32 bytes=3382 src=192.168.100.1 dst=192.168.100.147 sport=22 dport=39276 packets=21 bytes=3889 [ASSURED] mark=0 zone=0 use=2

1.3 udp流量格式：
> ipv4     2 udp      17 25 src=10.1.2.197 dst=192.168.100.1 sport=57074 dport=53 packets=4 bytes=236 [UNREPLIED] src=192.168.100.1 dst=192.168.100.147 sport=53 dport=57074 packets=0 bytes=0 mark=0 zone=0 use=2
> ipv4     2 udp      17 14 src=192.168.100.254 dst=192.168.100.147 sport=43329 dport=53 packets=2 bytes=118 [UNREPLIED] src=10.1.2.197 dst=192.168.100.254 sport=53 dport=43329 packets=0 bytes=0 mark=0 zone=0 use=2

1.4 其它格式类似, 每个一行包含了出入两个方向, 

1.5 把前述数据转化成一个go map, key是前一半的五元组，value是这个五元组的流量统计packets,bytes 


2. 完成当前的session的流量统计后，遍历每个session:
2.1 vip.go 中vipAddrInfoMap记录vip地址和uuid的映射关系
2.2 vip.go 中定义了vip的流量统计格式:
> type VipCounter struct {
>	Packets      uint64
>	Bytes        uint64
>	Source       string
>	Destination  string
>	Source6      string
>	Destination6 string
>	VipUuid      string
>}
2.3 如果session的前一半，且后一半dst ip都不是vip的ip, 忽略这个session
2.4 如果当前session在前一次session中不存在
2.4.1 如果前一半的dst ip是vip的ip, 则把前一半的流量加到入方向流量，把后一半的流量加到出方向流量
2.4.2 如果后一半的dst ip是vip的ip, 则把前一半的流量加到出方向流量，把后一半的流量加到入方向流量
2.5 如果当前session在前一次session中存在
2.5.1 如果前一半的dst ip是vip的ip, 则把前一半的流量的差值加到入方向流量，把后一半的流量的差值加到出方向流量
2.5.2 如果后一半的dst ip是vip的ip, 则把前一半的流量的差值加到出方向流量，把后一半的流量的差值加到入方向流量