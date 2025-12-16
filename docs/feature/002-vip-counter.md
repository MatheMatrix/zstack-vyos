5.5.0以前, vip counter通过读取tc规则获取。5.5.0开始vip不配置配置tc规则,只有打开了vip qos才配置tc规则
因此使用iptables计数器来实现vip counter功能

# vip 统计值
在vip.go中, setVipHandler添加vip, removeVipHandler删除vip

对iptables规则的处理，参数iptables.go封装的方法处理

## 添加vip的iptables规则
新增一个函数实现下面的逻辑，给vip添加iptables规则, 这个函数输入参数：vipInfo

1. 检查是否存在chain: vip.in.counter,使用命令:iptables -t nat -L vip.in.counter, 
   如果不存在，创建chain: iptables -t nat -N vip.in.counter
2. 检查是否存在chain是否关在到PREROUTING chain, 使用命令: iptables -t nat  -C PREROUTING -j vip.in.counter, 
   如果没有，加载chain: iptables -t nat -I PREROUTING -j vip.in.counter
3. 检查是否存在chain: vip.out.counter, 使用命令:iptables -t nat -L vip.out.counter, 
   如果不存在，创建chain: iptables -t nat -N vip.out.counter 
4. 检查是否存在chain是否关在到POSTROUTING chain, 使用命令: iptables -t nat  -C POSTROUTING -j vip.out.counter, 
    如果没有，加载chain: iptables -t nat -I POSTROUTING -j vip.out.counter 
5. 通过$vipInfo.OwnerEthernetMac找到对应的接口名称，如, eth1
6. 在查看是否存在规则，使用命令: iptables -t nat -C vip.in.counter -i eth1 -d vipInfo.Ip/32 -m comment --comment $vipInfo.VipUuid -j vip.in.counter, 
   如果不存在，则添加: iptables -t nat -A vip.in.counter -i eth1 -d $vipInfo.Ip/32 -m comment --comment $vipInfo.VipUuid -j RETURN
7. 在查看是否存在规则，使用命令: iptables -t nat -C vip.out.counter -o eth1 -s $vipInfo.Ip/32 -m comment --comment $vipInfo.VipUuid -j vip.out.counter, 
   如果不存在，则添加: iptables -t nat -A vip.out.counter -o eth1 -s $vipInfo.Ip/32 -m comment --comment $vipInfo.VipUuid -j RETURN

在setVipHandler的函数增加逻辑:
遍历cmd.Vips, 调用前面的函数为每个vip添加iptables规则

## 删除vip的iptables规则
新增一个函数实现下面的逻辑，给vip删除iptables规则, 这个函数输入参数：vipInfo

1. 通过$vipInfo.OwnerEthernetMac找到对应的接口名称，如, eth1
2. 在查看是否存在规则，使用命令: iptables -t nat -C vip.in.counter -i eth1 -d vipInfo.Ip/32 -m comment --comment $vipInfo.VipUuid -j vip.in.counter,
   如果存在，则删除: iptables -t nat -D vip.in.counter -i eth1 -d $vipInfo.Ip/32 -m comment --comment $vipInfo.VipUuid -j RETURN
3. 在查看是否存在规则，使用命令: iptables -t nat -C vip.out.counter -i eth1 -s $vipInfo.Ip/32 -m comment --comment $vipInfo.VipUuid -j vip.out.counter,
   如果存在，则删除: iptables -t nat -D vip.out.counter -i eth1 -s $vipInfo.Ip/32 -m comment --comment $vipInfo.VipUuid -j RETURN

在setVipHandler的函数增加逻辑:
遍历cmd.Vips, 调用前面的函数为每个vip删除iptables规则

## 读取iptables规则计数

添加一个函数: 通过iptables命令得到vip的流量统计:
每个vip的统计值包含:
vipUuid, vipIp, 入方向pkt计数，入方向octet计数，出方向pkt计数，出方向octet计数
通过如下命令获取方向计数：
> #  iptables-save -c | grep vip.in.counter
> :vip.in.counter - [0:0]
> [0:0] -A PREROUTING -i eth4 -j vip.in.counter
> [0:0] -A vip.in.counter -d 10.10.11.245/32 -m comment --comment 8c8818af9e1c4ebebdad42a75050531d -j RETURN
> [0:0] -A vip.in.counter -d 10.10.11.246/32 -m comment --comment 8c8818af9e1c4ebebdad42a75050531f -j RETURN

忽略前两行输出，[x:y] 代表入方向pkt计数，入方向octet计数， -d xx/32, xx代表vipIp, --comment yy, yy代表vipUuid

通过如下命令获取出方向计数：
> #  iptables-save -c | grep vip.out.counter
> :vip.out.counter - [0:0]
> [0:0] -A PREROUTING -i eth4 -j vip.out.counter
> [0:0] -A vip.out.counter -s 10.10.11.245/32 -m comment --comment 8c8818af9e1c4ebebdad42a75050531d -j RETURN
> [0:0] -A vip.out.counter -s 10.10.11.246/32 -m comment --comment 8c8818af9e1c4ebebdad42a75050531f -j RETURN

忽略前两行输出，[x:y] 代表出方向pkt计数，出方向octet计数， -s xx/32, xx代表vipIp, --comment yy, yy代表vipUuid

替换 func (c *vipCollector) Update 的函数逻辑
根据前后的函数逻辑，把统计值传给prom.Metric


## ipv6 vip
对于ipv6的vip重复前面的步骤
### 添加vip的iptables规则
区别是命令ip6tables替换iptables
### 删除vip的iptables规则
区别是命令ip6tables替换iptables
### 读取iptables规则计数
区别是命令ip6tables替换iptables