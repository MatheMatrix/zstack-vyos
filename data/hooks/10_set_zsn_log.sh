#!/bin/bash

. ./hook_function

ZSN_DIR="/var/log/zstack/zsn-agent"
ZSN_LOG_FILE="/var/log/zstack/zsn-agent/zsn-agent.log"

if [ -L ${ZSN_LOG_FILE} ]; then
    log_info "zsn-agent.log is soft link, will delete ..."
    rm -f ${ZSN_LOG_FILE}
    touch ${ZSN_LOG_FILE}
    find ${ZSN_DIR} -name "zsn-agent.log.*[0-9]" | xargs rm -f
else
    log_info "zsn-agent.log not soft link, nothing to do ..."
fi
