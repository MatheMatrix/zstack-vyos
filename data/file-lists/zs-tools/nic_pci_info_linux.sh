#!/bin/bash
printf "%-8s %-20s %-12s %-15s\n" "Iface" "MAC" "Driver" "PCI"

for path in /sys/class/net/*; do
    iface=$(basename "$path")

    # 忽略 lo 和明显的管理/伪接口
    case "$iface" in
        lo|bonding_masters|pimreg) continue ;;
    esac

    # 必须有 MAC 地址文件
    [ -f "$path/address" ] || continue
    MAC=$(cat "$path/address")

    # 有 device 才尝试取 PCI & driver
    if [ -L "$path/device" ] || [ -d "$path/device" ]; then
        PCI=$(basename "$(readlink -f "$path/device")")
        if [ -L "$path/device/driver" ]; then
            DRIVER=$(basename "$(readlink -f "$path/device/driver")")
        else
            DRIVER="-"
        fi
    else
        PCI="-"
        DRIVER="-"
    fi

    printf "%-8s %-20s %-12s %-15s\n" "$iface" "$MAC" "$DRIVER" "$PCI"
done