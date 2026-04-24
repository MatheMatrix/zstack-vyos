# Func Spec: VIP 流量计数 eBPF 化

> **模板参考**: ZNS `docs/templates/func-spec-template.md`

---

## 基本信息

| 字段 | 值 |
|------|----|
| **文档标题** | VIP 流量计数：eBPF TC Hook 实现方案 |
| **PRD 引用** | `docs/feature/004-vip-counter-ebpf-prd.md` |
| **版本** | v1.0 |
| **作者** | lycrsx |
| **日期** | 2026-04-22 |
| **状态** | Approved（已实机验证） |

---

## 1. 架构概览

### 1.1 组件图

```
[zvr 进程 (Go)]
       │
       ├─ initEbpfCollection()          ← 加载 BPF .o 一次，获取 ebpfObjs
       │       │
       │       └─ vip_counter.o (embed)  ← clang -target bpf 编译产物
       │
       ├─ ensureEbpfOnInterface(iface)   ← 每张 NIC 调用一次
       │       │
       │       └─ attachTCFilters()      ← clsact + BpfFilter (prio=1)
       │
       ├─ ebpfAddVip / ebpfDelVip        ← 增删 vip_set / vip_set6 map key
       │
       └─ updateCountersByEbpf()         ← 每次 Prometheus scrape 时读取 PERCPU map
               │
               └─ BPF PERCPU_HASH maps   ← 内核数据面直接累加，无锁

[内核数据面]
  eth0 clsact ingress: prio=1 vip_count_ingress (BPF, DA)
                       prio=49151 mirred→ifb0 (QoS IPv6)
                       prio=49152 mirred→ifb0 (QoS IPv4)
  eth0 clsact egress:  prio=1 vip_count_egress (BPF, DA)
  eth0 root HTB:       egress QoS shaping

[BPF maps]
  vip_set            HASH     key=__be32  val=u8          (IPv4 VIP 白名单)
  vip_ingress_stats  PERCPU_HASH key=__be32 val=vip_stat  (IPv4 入向)
  vip_egress_stats   PERCPU_HASH key=__be32 val=vip_stat  (IPv4 出向)
  vip_set6           HASH     key=[16]byte val=u8          (IPv6 VIP 白名单)
  vip_ingress_stats6 PERCPU_HASH key=[16]byte val=vip_stat (IPv6 入向)
  vip_egress_stats6  PERCPU_HASH key=[16]byte val=vip_stat (IPv6 出向)
```

**NAT 时序正确性**:
- TC ingress hook 在 NF_PREROUTING **之前** → dst IP 仍是 VIP（DNAT 尚未发生）
- TC egress hook 在 NF_POSTROUTING **之后** → src IP 已是 VIP（SNAT 已完成）

### 1.2 涉及模块

| 层级 | 路径 | 改动类型 |
|------|------|---------|
| BPF C 程序 | `plugin/ebpf/vip_counter.c` | new |
| BPF 编译产物 | `plugin/ebpf/vip_counter.o` | new（构建机编译，随 vendor 提交）|
| Go eBPF 集成 | `plugin/vip_ebpf.go` | new |
| Go VIP 管理 | `plugin/vip.go` | modify（4 处植入）|
| 依赖管理 | `plugin/go.mod` | modify（+cilium/ebpf, +netlink）|
| 依赖 vendor | `plugin/vendor/github.com/cilium/` | new |
| 依赖 vendor | `plugin/vendor/github.com/vishvananda/netlink/` | new |
| 安装 Hook | `data/hooks/05_install_package.sh` | modify |
| 后安装 Hook | `data/hooks/08_post_install.sh` | modify |
| RPM 仓库 | `data/repos/bpftool-6.8.0-2.oe2203sp3.x86_64.rpm` | new |

### 1.3 技术决策

| ID | 标题 | 选项 | 选择 | 理由 |
|----|------|------|------|------|
| D-001 | BPF 加载方式 | A: bpftool loadall B: cilium/ebpf 纯 Go | B | 零运行时依赖，自含编译，可嵌入 .o 文件 |
| D-002 | BPF 挂载点 | A: XDP B: TC clsact | B | XDP 无 egress hook；TC 支持 ingress+egress，兼容 mirred QoS |
| D-003 | 计数器数据结构 | A: HASH（有锁）B: PERCPU_HASH | B | 消除锁竞争，128 CPU 主机性能提升显著 |
| D-004 | qdisc 共享策略 | A: 独立 qdisc B: 与 QoS 共用 clsact | B | 每个 NIC 只允许一个 clsact；prio=1 BPF、prio=49151/49152 QoS mirred 互不干扰 |
| D-005 | 动态 NIC 监控 | A: 定时轮询 B: netlink.LinkSubscribe | B | 事件驱动，无延迟，无 CPU 浪费 |
| D-006 | 平台门控 | A: 总是启用 B: IsEuler2203() 门控 | B | 仅 OpenEuler 22.03 SP3 满足内核要求，其他平台 fallback conntrack |
| D-007 | clsact 迁移 | A: 直接添加 clsact B: 先删 sch_ingress 再添加 | A (fail-safe) | 若旧 sch_ingress 存在则先删除，迁移失败立即返回错误，不产生无 qdisc 的中间态 |

---

## 2. 功能点 (Features)

### F-001: BPF C 程序 — TC Ingress/Egress 计数

| 字段 | 值 |
|------|----|
| **来源场景** | SC-001, SC-004, SC-005, SC-006, SC-007 |
| **涉及层级** | BPF C（`plugin/ebpf/vip_counter.c`）|

**描述**: 两个 TC BPF 程序分别挂载在网卡 ingress 和 egress 方向。入向程序
检查目标 IP 是否在 `vip_set` 中，出向程序检查源 IP 是否在 `vip_set` 中，
命中则累加 `packets` 和 `bytes` 到对应 PERCPU_HASH map。

**行为定义**:

| 程序 | SEC | 检查字段 | map |
|------|-----|---------|-----|
| `vip_count_ingress` | `tc_ingress` | `ip->daddr` (IPv4) / `ip6->daddr` (IPv6) | `vip_ingress_stats` / `vip_ingress_stats6` |
| `vip_count_egress` | `tc_egress` | `ip->saddr` (IPv4) / `ip6->saddr` (IPv6) | `vip_egress_stats` / `vip_egress_stats6` |

**数据模型**:

```c
// plugin/ebpf/vip_counter.c
struct vip_stat {
    __u64 packets;
    __u64 bytes;
};

// 6 maps:
BPF_MAP_DEF(vip_set,            BPF_MAP_TYPE_HASH,         __be32,    u8,         1024)
BPF_MAP_DEF(vip_ingress_stats,  BPF_MAP_TYPE_PERCPU_HASH,  __be32,    vip_stat,   1024)
BPF_MAP_DEF(vip_egress_stats,   BPF_MAP_TYPE_PERCPU_HASH,  __be32,    vip_stat,   1024)
BPF_MAP_DEF(vip_set6,           BPF_MAP_TYPE_HASH,         __u8[16],  u8,         1024)
BPF_MAP_DEF(vip_ingress_stats6, BPF_MAP_TYPE_PERCPU_HASH,  __u8[16],  vip_stat,   1024)
BPF_MAP_DEF(vip_egress_stats6,  BPF_MAP_TYPE_PERCPU_HASH,  __u8[16],  vip_stat,   1024)
```

**边界值约束**:

| 参数 | 约束 | 说明 | 来源 |
|------|------|------|------|
| max_entries | 1024 | 支持最多 1024 个 VIP（IPv4 和 IPv6 各自独立） | NF-006 |
| 编译参数 | 必须带 `-g` 标志 | 内核 5.10 TC BPF 要求 BTF debug info | 实机验证 |
| eth->h_proto | 仅处理 IPv4 (0x0800) 和 IPv6 (0x86DD) | VLAN/QinQ 帧暂不处理（Q-1）| — |

**测试点**:

| TP ID | 类型 | 描述 | 预期结果 |
|-------|------|------|---------|
| TP-001 | integration | ICMP ping VIP → ingress stats 递增 | `vip_ingress_stats[vip]` packets/bytes 均增加 |
| TP-002 | integration | RS 回包经 SNAT → egress stats 递增 | `vip_egress_stats[vip]` packets/bytes 均增加 |
| TP-003 | integration | 非 VIP 流量 → stats 不递增 | 不影响 VIP 计数器 |
| TP-004 | integration | IPv6 VIP → vip_ingress_stats6/vip_egress_stats6 递增 | IPv6 map 正确 |

---

### F-002: Go BPF 加载与 TC 挂载

| 字段 | 值 |
|------|----|
| **来源场景** | SC-001, SC-011, SC-012, SC-013 |
| **涉及层级** | Go（`plugin/vip_ebpf.go`）|

**描述**: 通过 `//go:embed` 内嵌 BPF .o 文件，使用 cilium/ebpf 库加载 BPF Collection，
在每个物理 NIC 上确保挂载 clsact qdisc 和 BPF filter（prio=1, direct-action）。

**核心函数**:

```go
// 加载 BPF collection（全局一次）
func initEbpfCollection() error

// 在指定 NIC 上挂载 TC filter（幂等，已挂载则跳过）
func ensureEbpfOnInterface(iface string)

// 内部：添加/迁移 clsact qdisc
func ensureClsactQdisc(link netlink.Link) (migrated bool, err error)

// 内部：添加 ingress + egress BPF filter
func attachTCFilters(iface string, objs *vipEbpfObjects) error
```

**clsact 迁移逻辑**:

```
if clsact 已存在 → 直接使用
else if sch_ingress 存在 → 先添加 clsact（Add 失败立即返回 error，不删 sch_ingress）
                          → Add 成功后迁移 mirred filter → 删除 sch_ingress
else → 直接添加 clsact
```

**BpfFilter 参数**:

```go
netlink.BpfFilter{
    FilterAttrs: netlink.FilterAttrs{
        LinkIndex: link.Attrs().Index,
        Parent:    netlink.HANDLE_MIN_INGRESS, // or HANDLE_MIN_EGRESS
        Handle:    netlink.MakeHandle(1, 1),
        Priority:  1,
        Protocol:  syscall.ETH_P_ALL,          // 库内部 Swap16
    },
    Fd:           prog.FD(),
    Name:         "vip_ingress",
    DirectAction: true,
}
```

**边界值约束**:

| 参数 | 约束 | 说明 | 来源 |
|------|------|------|------|
| clsact Add 失败 | 立即返回 error，不继续 | 防止无 qdisc 中间态 | D-007 |
| link.AttachTCX | **禁止**使用 | 需要 kernel 6.6+，当前 5.10 | D-002 |
| Filter Priority | 1 | 低于 QoS mirred (49151/49152)，优先执行 | D-004 |

**测试点**:

| TP ID | 类型 | 描述 | 预期结果 |
|-------|------|------|---------|
| TP-005 | unit | initEbpfCollection 加载有效 .o | ebpfObjs 非 nil，6 maps 均非 nil |
| TP-006 | integration | ensureEbpfOnInterface 幂等调用 | 第二次调用无 error，tc filter show 只有 1 条 BPF 规则 |
| TP-007 | integration | sch_ingress 迁移场景 | 迁移后 clsact 存在，mirred filter 保留，QoS 正常 |
| TP-008 | unit | ebpfObjs map nil 检测 | 任意 map 为 nil 时 initEbpfCollection 返回 error |

---

### F-003: VIP 增删同步 BPF Map

| 字段 | 值 |
|------|----|
| **来源场景** | SC-008, SC-009, SC-010 |
| **涉及层级** | Go（`plugin/vip_ebpf.go`）|

**描述**: `ebpfAddVip` 向 `vip_set`（IPv4）或 `vip_set6`（IPv6）写入 VIP key，
`ebpfDelVip` 同时从 vip_set 和对应 stats map 中删除，彻底释放 map 条目。

**行为定义**:

```go
func ebpfAddVip(vipIP net.IP) {
    // IPv4: ip.To4() → __be32 key (网络字节序)
    // IPv6: ip.To16() → [16]byte key
    // BPF_NOEXIST 写入 vip_set/vip_set6
}

func ebpfDelVip(vipIP net.IP) {
    // 1. 删除 vip_set / vip_set6 条目
    // 2. 删除 vip_ingress_stats / vip_egress_stats 条目  ← 防止 map 满 + 旧数据继承
    // (IPv6 同理删 vip_ingress_stats6 / vip_egress_stats6)
}
```

**边界值约束**:

| 参数 | 约束 | 说明 | 来源 |
|------|------|------|------|
| 删除时必须清 stats map | 否则 max_entries=1024 会耗尽，且 IP 复用时继承旧计数 | 修复 Bug#3 | SC-009, SC-010 |

**测试点**:

| TP ID | 类型 | 描述 | 预期结果 |
|-------|------|------|---------|
| TP-009 | unit | 添加再删除 VIP，vip_set 条目消失 | map.Lookup(key) 返回 NotFound |
| TP-010 | unit | 删除 VIP 时 stats map 同步清除 | stats map Lookup(key) 返回 NotFound |
| TP-011 | unit | 重新添加同 IP VIP，stats 从 0 开始 | 计数器不继承历史值 |

---

### F-004: Prometheus metrics 读取 PERCPU map

| 字段 | 值 |
|------|----|
| **来源场景** | SC-001, SC-002, SC-007 |
| **涉及层级** | Go（`plugin/vip_ebpf.go`，`plugin/vip.go`）|

**描述**: `updateCountersByEbpf` 遍历 vip_ingress_stats 和 vip_egress_stats，
对每个 VIP key 的所有 CPU slot 求和，更新 `map[string]*VipCounter`。

**实现关键**:

```go
// PERCPU_HASH 迭代：values 为预分配 slice，直接传（非 &values）
values := make([]vipStat, numCPU)
iter := m.Iterate()
for iter.Next(&key, values) {     // ← values 不加 &
    var totalPkts, totalBytes uint64
    for _, v := range values {
        totalPkts  += v.Packets
        totalBytes += v.Bytes
    }
    // ...
}
```

**边界值约束**:

| 参数 | 约束 | 说明 | 来源 |
|------|------|------|------|
| 并发保护 | vip.go Update() 必须在 c.mu.Lock() 之后调用 updateCountersByEbpf | 防止 counters map 并发读写 | 修复 Bug#1 |
| goroutine 安全 | ebpfObjs 仅在 initEbpfCollection 中初始化，读取时检查 nil | — | — |

**测试点**:

| TP ID | 类型 | 描述 | 预期结果 |
|-------|------|------|---------|
| TP-012 | integration | 发送 100 ICMP 包到 VIP，scrape metrics | `zvr_vip_in_packets_total{ip=VIP}` = 100 |
| TP-013 | integration | 128 CPU 机器，PERCPU 累加正确 | 所有 CPU slot 求和值正确 |
| TP-014 | unit | counters map 并发读写无 data race | go test -race 无告警 |

---

### F-005: 动态 NIC 监控（netlink.LinkSubscribe）

| 字段 | 值 |
|------|----|
| **来源场景** | SC-011 |
| **涉及层级** | Go（`plugin/vip_ebpf.go`）|

**描述**: 使用 `netlink.LinkSubscribe` 监听内核 NIC 状态变化事件。当新网卡 UP
事件到达时，自动调用 `ensureEbpfOnInterface` 挂载 BPF filter，确保动态热插 NIC
无需重启 zvr 即可开始计数。

**行为定义**:
- 监听 goroutine 在 `initEbpfCollection` 时启动
- 接收 `netlink.LinkUpdate` 事件，过滤 `ifi_change != 0` 且 `flags & IFF_UP != 0`
- 对每个已有 VIP 的 NIC 调用 `ensureEbpfOnInterface`

**测试点**:

| TP ID | 类型 | 描述 | 预期结果 |
|-------|------|------|---------|
| TP-015 | manual | 运行中 ip link add dummy0 type dummy; ip link set dummy0 up | `tc filter show dev dummy0 ingress` 可见 BPF filter |

---

### F-006: 软件打包与 Hook 安装

| 字段 | 值 |
|------|----|
| **来源场景** | NF-003, NF-004 |
| **涉及层级** | 部署脚本（`data/hooks/`）|

**描述**: 在 zvr 安装阶段自动安装 bpftool RPM 并加载所需内核模块。

**`data/hooks/05_install_package.sh`**（在 `exit 0` 前新增）:

```bash
OPENEULER_RPMS="bpftool-6.8.0-2.oe2203sp3.x86_64.rpm"

if cat /etc/system-release 2>/dev/null | grep -q "openEuler"; then
    for file in ${OPENEULER_RPMS}; do
        rpm_path="${REPOS_PATH}/${file}"
        [ -f "${rpm_path}" ] || { log_info "can not find rpm: [${file}]"; continue; }
        pkg_name=$(rpm -qp --queryformat '%{NAME}' "${rpm_path}" 2>/dev/null)
        rpm -q "${pkg_name}" >/dev/null 2>&1 && { log_info "[${pkg_name}] already installed"; continue; }
        log_info "start install rpm: [${file}]"
        rpm -ivh "${rpm_path}" >> "${LOG_FILE}" 2>&1
    done
fi
```

**`data/hooks/08_post_install.sh`**（在 `exit 0` 前新增）:

```bash
if cat /etc/system-release 2>/dev/null | grep -q "openEuler"; then
    lsmod | grep -q sch_ingress || modprobe sch_ingress
    lsmod | grep -q cls_bpf    || modprobe cls_bpf
    log_info "eBPF TC modules loaded: sch_ingress, cls_bpf"
fi
```

**测试点**:

| TP ID | 类型 | 描述 | 预期结果 |
|-------|------|------|---------|
| TP-016 | integration | 全新 guest 执行安装 hook | bpftool 已安装，sch_ingress/cls_bpf 已加载 |
| TP-017 | integration | 重复执行安装 hook | 幂等，无 error，已安装包跳过 |

---

### F-007: vip.go 植入点

| 字段 | 值 |
|------|----|
| **来源场景** | SC-001, SC-008, SC-009, SC-012 |
| **涉及层级** | Go（`plugin/vip.go`）|

**描述**: vip.go 在 4 处调用 eBPF 接口，以 `utils.IsEuler2203()` 门控所有 eBPF 代码路径。

**植入位置**:

| 函数 | 位置 | 改动 |
|------|------|------|
| `initVipCounterChains()` | ~line 1091 | `if utils.IsEuler2203() { initEbpfCollection() }` |
| `SetVip()` | ~line 1138 | 获取 nicname 后调用 `ensureEbpfOnInterface(nicname)` + `ebpfAddVip(net.ParseIP(vip.Ip))` |
| `RemoveVip()` | ~line 1483 | `ebpfDelVip(net.ParseIP(vip.Ip))` + IPv6 |
| `vipCollector.Update()` | ~line 2050 | `c.mu.Lock()` **先于** eBPF 读取；`if ebpfObjs != nil { updateCountersByEbpf(c.counters) } else { c.updateCountersByConntrack() }` |

**边界值约束**:

| 参数 | 约束 | 说明 | 来源 |
|------|------|------|------|
| mutex 范围 | c.mu.Lock() 在 updateCountersByEbpf 之前获取 | 防 counters 并发 map 访问 | 修复 Bug#1 |
| IsEuler2203 门控 | 所有 eBPF 调用均包在 if 块内 | 其他平台 fallback conntrack | NF-001 |

---

## 3. 环境约束

| 项目 | 要求 | 实机验证结果 |
|------|------|------------|
| OS | OpenEuler 22.03 LTS-SP3 | ✅ |
| Kernel | ≥ 5.10（clsact / PERCPU_HASH 支持）| ✅ 5.10.0-182 |
| BPF JIT | `net.core.bpf_jit_enable=1` | ✅ 默认开启 |
| BTF | `/sys/kernel/btf/vmlinux` 存在 | ✅ |
| kernel modules | `sch_ingress`, `cls_bpf` 可 modprobe | ✅ |
| zvr 权限 | root (uid=0)，cap_bpf / cap_net_admin | ✅ |
| 构建机 | clang-12, libbpf-devel, llvm-12 | ✅ |

---

## 4. 已修复的 Bug（Code Review 阶段）

| Bug ID | 位置 | 描述 | 修复方式 |
|--------|------|------|---------|
| Bug#1 | `vip.go Update()` | mutex 在 updateCountersByEbpf 之后获取，导致 counters map 并发读写 | 将 c.mu.Lock() 移到函数顶部 |
| Bug#2 | `vip_ebpf.go attachTCFilters()` | clsact 迁移非原子：sch_ingress 删除后 clsact Add 失败，网卡无 qdisc | Add 失败立即 return error，不继续 |
| Bug#3 | `vip_ebpf.go ebpfDelVip()` | 删除 VIP 时仅从 vip_set 删除，stats map 条目残留，导致 map 满 + IP 复用继承旧计数 | ebpfDelVip 同步清理 4 个 stats map |
| Bug#4 | `vip_ebpf.go initEbpfVipCounter()` | BPF map nil 未检测，若加载不完整会在后续 Iterate() 时 panic | 添加 6 个 map 的 nil check，早退 |

---

## 5. 已知局限（Not Fixed）

| # | 位置 | 描述 | 影响 | 计划 |
|---|------|------|------|------|
| L-001 | `vip_counter.c` | VLAN/QinQ (802.1Q/802.1AD) 帧不处理 | vrouter 通常为 access port，影响极低 | 后续按需处理 |
| L-002 | `vip_counter.c` | 第一个包的 PERCPU NOEXIST race：多 CPU 同时初始化新 VIP key 时非赢者丢 1 包计数 | 误差极小，非精确计费场景可接受 | 可加 retry 修复 |
| L-003 | `attachTCFilters()` | clsact 迁移不完全原子：理想态应先 Add clsact 再删 sch_ingress | 已保证 Add 失败时 return error，窗口期很短 | 低优先级 |
