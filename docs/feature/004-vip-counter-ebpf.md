# 004 - VIP 流量计数：eBPF TC Hook 替代 conntrack 方案

> 本文档已按瀑布模型重组为独立的 PRD 和 Func Spec。

## 文档索引

| 文档 | 路径 | 说明 |
|------|------|------|
| **PRD** | [`004-vip-counter-ebpf-prd.md`](./004-vip-counter-ebpf-prd.md) | 产品需求文档：背景、用户故事、性能要求、验收标准 |
| **Func Spec** | [`004-vip-counter-ebpf-spec.md`](./004-vip-counter-ebpf-spec.md) | 功能规格：架构设计、功能点、数据模型、测试点、已知局限 |

## 一句话摘要

将 zstack-vyos vrouter 的 VIP 流量统计从 O(连接数) 的 conntrack 全量扫描，
替换为基于 eBPF TC Hook 的内核态计数（PERCPU_HASH 无锁），使 Prometheus 采集
延迟从数秒降至 < 100ms，并通过 clsact qdisc 与现有 QoS 规则共存。

## 实现状态

| 模块 | 状态 |
|------|------|
| `plugin/ebpf/vip_counter.c` | ✅ 完成 |
| `plugin/ebpf/vip_counter.o` | ✅ 已编译（BTF 嵌入）|
| `plugin/vip_ebpf.go` | ✅ 完成（含 4 个 bug fix）|
| `plugin/vip.go` 植入 | ✅ 完成 |
| `data/hooks/05_install_package.sh` | ✅ 完成 |
| `data/hooks/08_post_install.sh` | ✅ 完成 |
| 实机验证（172.25.116.164）| ✅ VIP 流量计数正常，metrics 端点响应正常 |
