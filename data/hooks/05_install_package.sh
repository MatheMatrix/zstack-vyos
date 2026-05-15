#!/bin/bash

. ./hook_function

X86_DEBS=" \
          iperf_2.0.4-5_amd64.deb \
          strace_4.5.20-2_amd64.deb \
          mlnx-ofed-kernel-modules_5.4.80-amd64-vyos_amd64.deb \
         "

# RPMs required for eBPF VIP counter on OpenEuler 22.03.
# NOTE: bpftool and libbpf are NOT runtime dependencies.
#   - libbpf-devel is only needed at BUILD TIME to compile plugin/ebpf/vip_counter.c.
#   - At runtime, cilium/ebpf loads the pre-compiled vip_counter.o (embedded via
#     go:embed in plugin/vip_ebpf.go) directly into the kernel via BPF syscalls.
#   - bpftool is a debug/inspection tool only.
EULER_2203_RPMS=""

EULER_OPENSSH_RPMS=" \
          openssh-8.8p1-37.oe2203sp3.x86_64.rpm \
          openssh-clients-8.8p1-37.oe2203sp3.x86_64.rpm \
          openssh-server-8.8p1-37.oe2203sp3.x86_64.rpm \
         "

EULER_OPENSSH_VERSION="8.8p1-37.oe2203sp3.x86_64"

function upgrade_euler_openssh() {
    local rpm_files=()

    for file in ${EULER_OPENSSH_RPMS}; do
        if [ ! -f "${REPOS_PATH}/${file}" ]; then
            log_info "can not find RPM package: [${file}]"
            return 1
        fi
        rpm_files+=("${REPOS_PATH}/${file}")
    done

    if rpm -q --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}' openssh 2>/dev/null | grep -q "^${EULER_OPENSSH_VERSION}$" && \
       rpm -q --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}' openssh-clients 2>/dev/null | grep -q "^${EULER_OPENSSH_VERSION}$" && \
       rpm -q --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}' openssh-server 2>/dev/null | grep -q "^${EULER_OPENSSH_VERSION}$"; then
        log_info "OpenSSH RPMs are already upgraded to [${EULER_OPENSSH_VERSION}]"
        return
    fi

    log_info "start upgrade OpenSSH RPMs: [${EULER_OPENSSH_RPMS}]"
    if ! rpm -Uvh "${rpm_files[@]}" >> "${LOG_FILE}" 2>&1; then
        log_info "upgrade OpenSSH RPMs failed"
        return 1
    fi
}


################
### use for install deb packages when zvr.bin is updated
#######

log_info "[05_install_package.sh]: start exec"

if [[ "${KERNEL_VERSION}" == "5.4.80-amd64-vyos" ]] && [[ "${ARCH}" == "x86_64" ]]; then
    for file in ${X86_DEBS}; do
        if [ ! -f "${REPOS_PATH}/${file}" ]; then
            log_info "can not find deb package: [$file]"
            continue
        fi
        log_info "start install deb package: [${file}]"
        package_name=${file%%_*}
        if dpkg -l | grep -q ${package_name}; then
            log_info "package [${package_name}] is already installed"
            continue
        fi
        /usr/bin/dpkg -i ${REPOS_PATH}/${file}
    done
fi

OS="vyos 1.1.7"
if [ -f /etc/system-release ]; then
    OS=$(cat /etc/system-release | awk '{print $1,$2,$3}')
fi

if [ "${OS}" == "openEuler release 22.03" ]; then
    for pkg in ${EULER_2203_RPMS}; do
        if rpm -q "${pkg}" &>/dev/null; then
            log_info "RPM [${pkg}] is already installed"
            continue
        fi
        rpm_file=$(find "${REPOS_PATH}" -name "${pkg}-*.rpm" | head -1)
        if [ -z "${rpm_file}" ]; then
            log_info "can not find RPM package: [${pkg}], trying yum"
            yum install -y "${pkg}" >> "${LOG_FILE}" 2>&1 || log_info "yum install [${pkg}] failed"
            continue
        fi
        log_info "start install RPM package: [${rpm_file}]"
        rpm -ivh "${rpm_file}" >> "${LOG_FILE}" 2>&1 || log_info "rpm install [${rpm_file}] failed"
    done
fi

if [[ "${OS}" == "openEuler release 22.03" ]] && [[ "${ARCH}" == "x86_64" ]]; then
    upgrade_euler_openssh || exit 1
fi

exit 0
