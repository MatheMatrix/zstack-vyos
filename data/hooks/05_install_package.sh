#!/bin/bash

. ./hook_function

X86_DEBS=" \
          iperf_2.0.4-5_amd64.deb \
          strace_4.5.20-2_amd64.deb \
         "

ARM_DEBS=" \
         libpython2.7-minimal_2.7.18-8_arm64.deb \
         python2.7-minimal_2.7.18-8_arm64.deb \
         "
################
### use for install deb packages when zvr.bin is updated
#######

log_info "[05_install_package.sh]: start exec"

if [[ "${KERNEL_VERSION}" == "5.4.80-amd64-vyos" ]] && [[ "${ARCH}" == "x86_64" ]]; then
    for i in ${X86_DEBS}; do
        if [ ! -f "${REPOS_PATH}/${i}" ]; then
            log_info "can not find deb package: [$i]"
            continue
        fi
        log_info "start install deb package: [${i}]"
        /usr/bin/dpkg -i ${REPOS_PATH}/${i}
    done
fi

if [[ "${ARCH}" == "aarch64" ]]; then
    dpkg -l python2.7
    if [ $? -ne 0 ];then
        for i in ${ARM_DEBS}; do
            dpkg -i ${REPOS_PATH}/${i}
        done
        sudo ln -s /usr/bin/python2.7 /usr/bin/python
    fi
fi

exit 0
