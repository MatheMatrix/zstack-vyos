#!/bin/bash

. ./hook_function

X86_DEBS=" \
          iperf_2.0.4-5_amd64.deb \
          strace_4.5.20-2_amd64.deb \
          mlnx-ofed-kernel-modules_5.4.80-amd64-vyos_amd64.deb \
         "

EULER_HAPROXY_RPM="haproxy-3.2.19-3.el8.x86_64.rpm"
EULER_HAPROXY_VERSION="3.2.19-3.el8.x86_64"

function upgrade_euler_haproxy() {
    local rpm_file="${REPOS_PATH}/${EULER_HAPROXY_RPM}"
    local installed_version

    if [ "${ARCH}" != "x86_64" ]; then
        return
    fi

    installed_version=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}' haproxy 2>/dev/null || true)
    if [ "${installed_version}" == "${EULER_HAPROXY_VERSION}" ]; then
        log_info "HAProxy RPM is already upgraded to [${EULER_HAPROXY_VERSION}]"
        return
    fi

    if [ ! -f "${rpm_file}" ]; then
        log_info "can not find HAProxy RPM package: [${rpm_file}]"
        return
    fi

    log_info "start upgrade HAProxy RPM from [${installed_version:-not installed}] to [${EULER_HAPROXY_VERSION}]"
    rpm -Uvh "${rpm_file}" >> "${LOG_FILE}" 2>&1 || log_info "upgrade HAProxy RPM failed: [${rpm_file}]"
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
    upgrade_euler_haproxy
fi

exit 0
