5.5.0以前, 配置vip的时候，默认配置tc qos规则, 5.5.0以后, 默认不配置vip的tc规则

# 旧代码

vip.go的全局变量: totalQosRules记录了当前vip qos rule
在创建vip的处理函数中: setVipHandler, 分别调用 setVipByLinux, 或者 setVip
setVipByLinux和setVip的处理过程中, 如果utils.IsConfigTcForVipQos就会添加默认vip的qos规则

# 修改要求

删除setVipByLinux和setVip的处理过程中, 删除utils.IsConfigTcForVipQos的处理逻辑