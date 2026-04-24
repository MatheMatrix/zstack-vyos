# PRD: VIP 流量计数 eBPF 化

> **模板参考**: ZNS `docs/templates/prd-template.md`

---

## 基本信息

| 字段 | 值 |
|------|----|
| **文档标题** | VIP 流量计数：eBPF TC Hook 替代 conntrack 方案 |
| **关联设计** | `002-vip-counter-1.md`（原 conntrack 方案） |
| **版本** | v1.0 |
| **作者** | lycrsx |
| **日期** | 2026-04-22 |
| **状态** | Approved |

---

## 1. 背景与目标

### 1.1 问题描述

zstack-vyos vrouter 通过读取 `/proc/net/nf_conntrack` 全量扫描 session 来统计 VIP 流量
（`002-vip-counter-1.md`）。该方案在高流量场景下存在严重性能问题：

- 每次采集需要全量扫描 conntrack 表，复杂度 O(N)，N 为总连接数
- 高流量时连接表可达百万级，单次读取耗时数秒，Prometheus metrics 延迟超可接受范围
- Go 侧维护 `previousStats` map 带来内存和 GC 压力
- conntrack 表本身在高流量下有锁竞争，采集行为进一步加剧内核压力

### 1.2 目标

1. 将 VIP 流量统计替换为 eBPF TC Hook 方案，在内核数据包路径上直接累加计数器
2. 采集复杂度从 O(连接数) 降至 O(VIP 数)，实现常数时间读取
3. 精确识别 DNAT/SNAT（IPVS full-NAT）场景下的 VIP 方向性流量
4. 支持 IPv4 + IPv6 双栈 VIP
5. 在不破坏现有 QoS TC 规则的前提下共存

### 1.3 非目标 (Out of Scope)

- 不替换现有的 QoS TC 规则（clsact mirred → ifb0）
- 不统计非 VIP 普通转发流量（后续功能）
- 不支持 Debian/Ubuntu 平台（仅 OpenEuler 22.03 SP3）
- 不在运行时动态编译 BPF 程序（BPF .o 文件随 zvr 包发布）

---

## 2. 用户角色

| ID | 角色名称 | 描述 |
|----|---------|------|
| R-01 | ZStack 管理平台 | 通过 Prometheus metrics 端点拉取 VIP 流量数据，用于计费和监控告警 |
| R-02 | VRouter 运维人员 | 通过 `http://<vrouter>:7272/metrics` 验证 VIP 流量统计正确性 |

---

## 3. 用户故事与场景

### Story S-001: 高流量下 VIP 流量采集无性能抖动

**As a** ZStack 管理平台 (R-01), **I want** VIP 流量指标在百万连接场景下能在 < 100ms 内返回,
**so that** 计费系统不会因 metrics 超时而丢失数据。

**优先级**: P0

#### 场景

| ID | 标题 | Given | When | Then | 标签 |
|----|------|-------|------|------|------|
| SC-001 | 正常 VIP 流量计数 | vrouter 上已配置 EIP VIP `172.25.116.170`，后端 RS 为 `192.168.200.241`，ICMP ping 流量持续发送 | 抓取 `GET /metrics` | `zvr_vip_in_bytes_total{ip="172.25.116.170"}` 和 `zvr_vip_out_bytes_total{ip="172.25.116.170"}` 持续递增，单次采集耗时 < 100ms | happy-path |
| SC-002 | 百万连接下采集时间稳定 | conntrack 表有 1,000,000 条 TCP session，vrouter 上有 10 个 VIP | 抓取 `/metrics` | 采集耗时 < 100ms（与连接数无关，仅与 VIP 数成线性）| performance |
| SC-003 | 无 VIP 时指标为空 | vrouter 上未配置任何 VIP | 抓取 `/metrics` | `zvr_vip_*_total` 系列指标为空，无错误日志 | edge-case |

---

### Story S-002: DNAT/SNAT 场景下方向性计数准确

**As a** ZStack 管理平台 (R-01), **I want** 入向（到 VIP 的流量）和出向（从 VIP 出的流量）分别准确计数,
**so that** 双向流量报表符合计费规则。

**优先级**: P0

#### 场景

| ID | 标题 | Given | When | Then | 标签 |
|----|------|-------|------|------|------|
| SC-004 | 入向（DNAT 前）正确识别 VIP | 外部客户端访问 EIP `172.25.116.170`，DNAT 转给 RS `192.168.200.241` | 发送 100 个包、总共 148,000 字节 | `zvr_vip_in_packets_total` 增加 100，`zvr_vip_in_bytes_total` 增加 148,000 | happy-path |
| SC-005 | 出向（SNAT 后）正确识别 VIP | RS `192.168.200.241` 回包，经 SNAT 后 src 变为 VIP `172.25.116.170` | RS 回包 100 个 | `zvr_vip_out_packets_total` 增加 100，`zvr_vip_out_bytes_total` 正确 | happy-path |
| SC-006 | IPVS full-NAT 模式下计数正确 | VIP 经 IPVS full-NAT 转发（src 也被替换） | 流量通过 IPVS full-NAT VIP | 入向和出向计数均正确，无漏计 | happy-path |
| SC-007 | IPv6 VIP 流量计数 | 配置 IPv6 VIP `2001:db8::1` | IPv6 流量到 VIP | `zvr_vip_in_bytes_total{ip="2001:db8::1"}` 正确递增 | happy-path |

---

### Story S-003: VIP 动态增删不影响计数

**As a** ZStack 管理平台 (R-01), **I want** VIP 创建和删除时计数器正确同步,
**so that** 计费数据不出现残留累计或误归属。

**优先级**: P1

#### 场景

| ID | 标题 | Given | When | Then | 标签 |
|----|------|-------|------|------|------|
| SC-008 | 新建 VIP 立即开始计数 | vrouter 上无 VIP | 调用 SetVip 添加 VIP `10.0.0.1` | 新增流量立即被 `10.0.0.1` 的计数器捕获 | happy-path |
| SC-009 | 删除 VIP 释放 map 条目 | VIP `10.0.0.1` 已有计数 | 调用 RemoveVip 删除 `10.0.0.1` | BPF map 中 `10.0.0.1` 条目被删除，后续流量不再计入，map 容量被释放 | happy-path |
| SC-010 | VIP IP 复用不继承旧计数 | VIP `10.0.0.1` 被删除后再次添加 | 重新 SetVip `10.0.0.1` | 计数器从 0 开始，不继承删除前的统计 | edge-case |
| SC-011 | 动态新增网卡自动挂载 BPF | vrouter 运行中新增物理网卡 `eth2` | 热插 NIC 或调用 EnsureEbpfOnInterface | `eth2` 自动挂载 clsact + BPF filter，新 VIP 流量正常统计 | happy-path |

---

### Story S-004: 与现有 QoS TC 规则共存

**As a** VRouter 运维人员 (R-02), **I want** eBPF 计数不破坏已有 QoS 限速规则,
**so that** 升级后用户带宽限制行为不变。

**优先级**: P0

#### 场景

| ID | 标题 | Given | When | Then | 标签 |
|----|------|-------|------|------|------|
| SC-012 | clsact 与 QoS mirred 规则共存 | 网卡已有 clsact qdisc 和 prio=49151/49152 的 mirred ingress filter | 添加 eBPF filter (prio=1) | QoS mirred filter 正常保留，tc filter show 可见两者并列，带宽限制行为不变 | happy-path |
| SC-013 | sch_ingress 迁移到 clsact 不丢 QoS | 网卡存在旧式 sch_ingress（无 clsact），且有 mirred filter | 触发 clsact 迁移 | mirred filter 被正确迁移到 clsact ingress，QoS 恢复，无流量黑洞 | edge-case |
| SC-014 | VIP eBPF 不影响 egress HTB 限速 | 网卡 root 已有 HTB qdisc 用于 egress QoS | 同时挂载 VIP eBPF egress filter | HTB 依然生效，egress 限速行为不变 | happy-path |

---

## 4. 性能要求

| ID | 指标 | 目标值 | 测试条件 | 关联场景 |
|----|------|--------|---------|---------|
| PERF-001 | metrics 采集延迟 | < 100ms | conntrack 表 1,000,000 条，VIP 数量 ≤ 1,024 | SC-002 |
| PERF-002 | BPF 程序单包处理开销 | < 1µs per packet（JIT 开启时） | 10Gbps 线速，NIC 驱动开启 JIT | — |
| PERF-003 | BPF map 内存占用 | ≤ 128MB | 128 CPU × 4 stats maps × 1,024 VIP | — |

---

## 5. 非功能需求

| ID | 类别 | 要求 | 关联场景 |
|----|------|------|---------|
| NF-001 | 平台兼容性 | 仅在 OpenEuler 22.03 SP3（kernel 5.10）启用 eBPF；其他平台 fallback 到 conntrack | SC-001 |
| NF-002 | 向后兼容 | VIP metrics 端点格式不变，只改底层计数方式 | SC-001 |
| NF-003 | 内核模块 | 依赖 `sch_ingress` / `cls_bpf` 模块，须在 hook 安装阶段自动 modprobe | SC-012 |
| NF-004 | 零运行时编译 | BPF .o 文件随 zvr 包发布，guest OS 不需要 clang/llvm | SC-001 |
| NF-005 | 故障降级 | BPF 加载失败时自动 fallback 到 conntrack 方案，不影响 vrouter 正常工作 | SC-003 |
| NF-006 | map 容量 | 支持最多 1,024 个 VIP（IPv4 + IPv6 分别独立计数） | SC-009 |

---

## 6. 验收标准汇总

| 场景 ID | 标题 | Story | 标签 | 可自动化 |
|---------|------|-------|------|---------|
| SC-001 | 正常 VIP 流量计数 | S-001 | happy-path | Yes |
| SC-002 | 百万连接下采集时间稳定 | S-001 | performance | Yes |
| SC-003 | 无 VIP 时指标为空 | S-001 | edge-case | Yes |
| SC-004 | 入向 DNAT 前正确识别 VIP | S-002 | happy-path | Yes |
| SC-005 | 出向 SNAT 后正确识别 VIP | S-002 | happy-path | Yes |
| SC-006 | IPVS full-NAT 计数正确 | S-002 | happy-path | Yes |
| SC-007 | IPv6 VIP 计数 | S-002 | happy-path | Yes |
| SC-008 | 新建 VIP 立即计数 | S-003 | happy-path | Yes |
| SC-009 | 删除 VIP 释放 map | S-003 | happy-path | Yes |
| SC-010 | VIP IP 复用不继承旧计数 | S-003 | edge-case | Yes |
| SC-011 | 动态 NIC 自动挂载 BPF | S-003 | happy-path | Manual |
| SC-012 | clsact 与 QoS mirred 共存 | S-004 | happy-path | Yes |
| SC-013 | sch_ingress 迁移到 clsact | S-004 | edge-case | Manual |
| SC-014 | eBPF 不影响 egress HTB | S-004 | happy-path | Yes |

**统计**: 总场景 14 | Happy-path 9 | Edge-case 3 | Performance 2

---

## 7. 约束与依赖

| 依赖项 | 负责方 | 状态 | 风险 |
|--------|--------|------|------|
| OpenEuler 22.03 SP3 内核支持 clsact / cls_bpf | 操作系统 | ✅ 实机验证通过 | 低 |
| cilium/ebpf v0.16.0 Go 库 | 第三方开源 | ✅ 已 vendor | 低 |
| vishvananda/netlink v1.1.0 Go 库 | 第三方开源 | ✅ 已 vendor | 低 |
| bpftool v6.8.0 RPM（OpenEuler 专用，749KB）| 构建机获取 | ✅ 已获取 | 低 |
| BPF .o 文件构建机编译（clang-12 + libbpf-devel）| CI 流程 | ✅ 已验证 | 低 |
| IsEuler2203() 平台检测函数 | zstack-vyos utils | ✅ 已有 | 低 |

---

## 8. 开放问题

| # | 问题 | 状态 |
|---|------|------|
| Q-1 | VLAN/QinQ 封装场景下 BPF 程序需要解析 vlan header | Open — 当前 vrouter 为 access port，暂不处理 |
| Q-2 | 第一个包多核竞争（PERCPU NOEXIST race）导致极小概率丢 1 包的计数 | Open — 非精确计费场景可接受，精确场景待 retry 修复 |
| Q-3 | 后续全网卡流量可视化是否复用本 BPF 框架 | Open — 当前设计已预留 prio=2 slot，待后续 `nic_traffic.c` 扩展 |

---

## 9. 故障排查指南

本章面向运维人员和 ZStack 支持工程师，提供系统化的 eBPF 流量计数故障诊断步骤。

### 9.1 确认当前运行模式

zvr 启动时会在日志（`/var/log/zvr/zvr.log`）中打印运行模式：

```
# eBPF 模式（正常）
VIP counter: OpenEuler 22.03 detected, attempting eBPF mode
eBPF VIP counter: loading vip_counter.o from embedded bytes (XXXX bytes)
eBPF VIP counter: collection loaded OK — tcIngress.FD=5 tcEgress.FD=6; attaching to NICs
eBPF VIP counter: ready — TC filters attached, link watcher started
VIP counter: eBPF mode active

# conntrack 降级模式（eBPF 加载失败时）
VIP counter: eBPF init failed, falling back to conntrack mode: <具体错误>

# 非 OpenEuler 平台
VIP counter: non-OpenEuler platform, using conntrack mode
```

**快速检查命令：**
```bash
grep -E "VIP counter:|eBPF VIP counter:" /var/log/zvr/zvr.log | tail -10
```

---

### 9.2 检查 TC filter 是否挂载

eBPF 计数依赖 TC ingress/egress filter 挂在公网网卡上：

```bash
# 替换 eth0 为实际公网网卡名
tc filter show dev eth0 ingress
tc filter show dev eth0 egress

# 正常输出示例（prio=1 的 bpf filter）：
# filter protocol all pref 1 bpf chain 0
# filter protocol all pref 1 bpf chain 0 handle 0x1 vip_ingress direct-action not_in_hw
```

若 ingress filter 缺失，eBPF 计数不会工作。查看 zvr 日志确认原因：
```bash
grep "eBPF: attaching filter\|eBPF: failed to attach\|eBPF: filter.*attached" /var/log/zvr/zvr.log
```

---

### 9.3 检查 clsact qdisc 是否存在

```bash
tc qdisc show dev eth0

# 正常：包含 clsact
# qdisc clsact ffff: dev eth0 parent ffff:fff1

# 异常：只有 ingress（旧式，应被迁移到 clsact）
# qdisc ingress ffff: dev eth0 parent ffff:fff1
```

若没有 clsact，可手动触发重新初始化（重启 zvr 或发一次 SetVip 请求）。

---

### 9.4 检查 BPF map 内容（需 bpftool）

> 注意：bpftool 仅用于调试，不是运行时依赖。需手动安装：`yum install -y bpftool`

```bash
# 查看所有 BPF map
bpftool map show

# 查看 VIP 集合（哪些 IP 被监控）
bpftool map dump name vip_set

# 正常输出示例（有 VIP 10.0.0.1 时）：
# key: 0a 00 00 01   value: 01

# 查看 ingress 流量统计
bpftool map dump name vip_ingress_stats

# 查看 egress 流量统计
bpftool map dump name vip_egress_stats

# IPv6 版本
bpftool map dump name vip_set6
bpftool map dump name vip_ingress_stats6
```

---

### 9.5 验证 VIP 是否正确注册

VIP 必须同时出现在：①Prometheus metrics、②BPF `vip_set` map

```bash
# 1. 检查 Prometheus metrics（替换 IP）
curl -s http://127.0.0.1:7272/metrics | grep 'vip_in_bytes_total{' | grep '172.25.116.170'

# 2. 检查 BPF map（16 进制 IP）
bpftool map dump name vip_set
# 10.0.0.1 的 hex = 0a 00 00 01

# 3. 检查 zvr 日志中 VIP 注册记录（需 debug 日志级别）
grep "VIP eBPF: registering" /var/log/zvr/zvr.log
```

若 VIP 不在 `vip_set` 中但在 metrics 中存在，说明 eBPF 模式未加载（计数全为 0）。

---

### 9.6 流量计数为 0 的排查流程

```
metrics 全为 0
    │
    ├── eBPF 模式未激活？
    │       → grep "VIP counter:" /var/log/zvr/zvr.log
    │       → 若为 conntrack 模式，检查 conntrack 是否工作
    │
    ├── TC filter 未挂载？
    │       → tc filter show dev <公网网卡> ingress
    │       → 查看 zvr 日志 "failed to attach TC filters"
    │
    ├── VIP 未注册到 BPF map？
    │       → bpftool map dump name vip_set
    │       → 若为空，重新触发 SetVip（ZStack 重新下发规则）
    │
    └── 流量未经过该网卡？
            → tcpdump -i eth0 -n dst <VIP_IP> -c 5
            → 确认流量确实走公网网卡
```

---

### 9.7 常见错误及处理

| 错误信息 | 可能原因 | 处理方法 |
|---------|---------|---------|
| `ebpf: load spec: ...` | vip_counter.o 损坏或 kernel 不支持某 BPF 特性 | 确认 kernel ≥ 5.10；检查 `cat /proc/version` |
| `ebpf: new collection: operation not permitted` | 进程无 CAP_BPF 或 CAP_SYS_ADMIN | 确认 zvr 以 root 运行 |
| `add clsact on eth0: file exists` | clsact 已存在（正常，idempotent） | 无需处理 |
| `filter replace vip_ingress: no such device` | 网卡名错误或网卡不存在 | 检查 `ip link show` 网卡列表 |
| `failed to add IPv4 VIP ... to vip_set: map full` | VIP 超过 1024 个上限 | 联系 ZStack 开发扩大 map 容量（修改 `vip_counter.c` 中 `max_entries`） |
| VIP metrics 恒为 0，但 filter 已挂载 | DNAT/SNAT 导致包在 TC 处理时 IP 已被 NAT | 确认 TC ingress 在 DNAT 之前（应在 NET_RX 路径，正常情况下满足） |

---

### 9.8 开启 Debug 日志

zvr 默认日志级别为 Info。切换到 Debug 可看到每次 metrics 采集、VIP 注册等详细过程：

```bash
# 临时（发送 SIGUSR1 切换 logrus 级别，若 zvr 支持动态日志）
kill -USR1 $(pgrep zvr)

# 或重启 zvr 并在配置中设置 log level = debug
# 具体方式参考 zvr 部署文档
```

Debug 级别关键日志前缀：
- `eBPF: reading stats for N tracked VIPs` — 每次 metrics 采集
- `eBPF: IPv4 VIP X.X.X.X added to vip_set map` — VIP 注册
- `eBPF: netlink RTM_NEWLINK for ethX` — 网卡热插
- `VIP eBPF: registering IPv4 VIP X.X.X.X` — SetVip 触发注册
- `VIP metrics: eBPF mode — collecting stats for N VIPs` — metrics 采集入口
