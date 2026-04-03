#!/usr/bin/env python3

import fcntl
import json
import os
import re
import signal
import subprocess
import sys
from datetime import datetime


LOG_FILE = "/var/log/snat_conntrack.log"
LOCK_FILE = "/var/run/snat-log-collector.lock"
RUNTIME_ENV_FILE = "/etc/zstack/snat-log.env"
CONNTRACK_CMD = [
    "stdbuf",
    "-oL",
    "conntrack",
    "-E",
    "--event-mask",
    "NEW,DESTROY",
    "-o",
    "timestamp,id",
]

_stop = False
_child = None
_reopen = False


KV_PATTERNS = {
    "src": re.compile(r"(?:^|\s)src=([^\s]+)"),
    "dst": re.compile(r"(?:^|\s)dst=([^\s]+)"),
    "sport": re.compile(r"(?:^|\s)sport=([^\s]+)"),
    "dport": re.compile(r"(?:^|\s)dport=([^\s]+)"),
    "packets": re.compile(r"(?:^|\s)packets=([^\s]+)"),
    "bytes": re.compile(r"(?:^|\s)bytes=([^\s]+)"),
}
EVENT_RE = re.compile(r"\[(NEW|DESTROY)\]")
PROTO_RE = re.compile(r"\b(tcp|udp|icmp)\b")


def ensure_log_path():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def load_runtime_env(path):
    if not os.path.isfile(path):
        return None

    env = {}
    with open(path, "r") as fp:
        for raw in fp:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            env[key] = value
    return env


def acquire_lock():
    lock_fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        return None
    return lock_fd


def handle_stop_signal(_signum, _frame):
    global _stop
    _stop = True
    if _child is not None and _child.poll() is None:
        _child.terminate()


def handle_hup_signal(_signum, _frame):
    global _reopen
    _reopen = True


def list_values(line, key):
    return KV_PATTERNS[key].findall(line)


def first_or_default(items, default=""):
    if items:
        return items[0]
    return default


def to_counter(value):
    if value.isdigit():
        return int(value)
    return 0


def now_utc_ms():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_business_record(line, vpc_uuid, vpc_default_ip, mgmt_ips):
    event_m = EVENT_RE.search(line)
    event = event_m.group(1) if event_m else "UNKNOWN"

    proto_m = PROTO_RE.search(line)
    protocol = proto_m.group(1) if proto_m else "unknown"

    src_values = list_values(line, "src")
    dst_values = list_values(line, "dst")
    sport_values = list_values(line, "sport")
    dport_values = list_values(line, "dport")

    src1 = first_or_default(src_values, "-")
    dst1 = first_or_default(dst_values, "-")
    src2 = src_values[1] if len(src_values) > 1 else "-"
    dst2 = dst_values[1] if len(dst_values) > 1 else "-"

    # Keep non-standard/incomplete conntrack lines for troubleshooting;
    # only drop records that explicitly match management-plane IPs.
    # Only filter management-plane traffic in the original direction.
    # Reply tuple may legitimately contain SNAT address on mgmt NIC.
    if src1 in mgmt_ips or dst1 in mgmt_ips:
        return None

    sport1 = first_or_default(sport_values, "-")
    dport1 = first_or_default(dport_values, "-")
    sport2 = sport_values[1] if len(sport_values) > 1 else "-"
    dport2 = dport_values[1] if len(dport_values) > 1 else "-"

    packets = to_counter(first_or_default(list_values(line, "packets"), "0"))
    bytes_count = to_counter(first_or_default(list_values(line, "bytes"), "0"))

    record = {
        "event": event,
        "level": "INFO",
        "timestamp": now_utc_ms(),
        "protocol": protocol,
        "orig_src": "%s:%s" % (src1, sport1),
        "orig_dst": "%s:%s" % (dst1, dport1),
        "repl_src": "%s:%s" % (src2, sport2),
        "repl_dst": "%s:%s" % (dst2, dport2),
        "packets": packets,
        "bytes": bytes_count,
        "vpcUuid": vpc_uuid,
        "vpcDefaultIp": vpc_default_ip,
    }
    return json.dumps(record, separators=(",", ":"))


def run():
    global _child, _reopen

    ensure_log_path()

    runtime_env = load_runtime_env(RUNTIME_ENV_FILE)
    if runtime_env is None:
        return 0

    vpc_uuid = runtime_env.get("VPC_UUID", "").strip()
    vpc_default_ip = runtime_env.get("VPC_DEFAULT_IP", "").strip()
    if not vpc_uuid:
        return 0

    mgmt_ips = set(
        x
        for x in [
            runtime_env.get("MN_VIP", "").strip(),
            runtime_env.get("MN_IP", "").strip(),
            runtime_env.get("MN_PEER_IP", "").strip(),
            runtime_env.get("MGMT_IP", "").strip(),
        ]
        if x
    )

    lock_fd = acquire_lock()
    if lock_fd is None:
        return 0

    signal.signal(signal.SIGTERM, handle_stop_signal)
    signal.signal(signal.SIGINT, handle_stop_signal)
    signal.signal(signal.SIGHUP, handle_hup_signal)

    with os.fdopen(lock_fd, "r"):
        log_fp = open(LOG_FILE, "a", buffering=1)
        try:
            try:
                _child = subprocess.Popen(
                    CONNTRACK_CMD,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
            except OSError as exc:
                log_fp.write("[snat-log-collector] failed to start command: %s\n" % exc)
                log_fp.flush()
                return 127

            if _child.stdout is None:
                return 1

            try:
                for line in _child.stdout:
                    if _stop:
                        break

                    if _reopen:
                        log_fp.close()
                        log_fp = open(LOG_FILE, "a", buffering=1)
                        _reopen = False

                    msg = parse_business_record(line, vpc_uuid, vpc_default_ip, mgmt_ips)
                    if msg is None:
                        continue

                    log_fp.write(msg + "\n")
                    log_fp.flush()
            finally:
                if _child.poll() is None:
                    _child.terminate()
                    try:
                        _child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        _child.kill()
                        _child.wait()

            return _child.returncode if _child.returncode is not None else 1
        finally:
            log_fp.close()


if __name__ == "__main__":
    sys.exit(run())
