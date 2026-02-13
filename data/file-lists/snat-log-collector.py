#!/usr/bin/env python3

import collections
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime


LOG_FILE = "/var/log/snat_conntrack.log"
STATS_FILE = "/var/log/snat_conntrack_stats.log"
LOCK_FILE = "/var/run/snat-log-collector.lock"
RUNTIME_ENV_FILE = "/etc/zstack/snat-log.env"
STATS_INTERVAL = 60  # seconds between stats flushes
CONNTRACK_CMD = [
    "stdbuf",
    "-oL",
    "conntrack",
    "-E",
    "--event-mask",
    "NEW,DESTROY",
    "-o",
    "timestamp,id",
    "--buffer-size",
    "8388608",  # 8 MB netlink socket buffer; requires net.core.rmem_max >= 8388608
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


# ---------------------------------------------------------------------------
# Performance statistics
# ---------------------------------------------------------------------------

class _Bucket:
    """One-second accumulator."""
    __slots__ = ("rx", "tx", "drop_mgmt", "drop_skip",
                 "parse_us", "write_us", "wait_us", "n")

    def __init__(self):
        self.rx = self.tx = self.drop_mgmt = self.drop_skip = 0
        self.parse_us = self.write_us = self.wait_us = self.n = 0


class StatsCollector:
    """
    Rolling-window statistics collector.

    Maintains per-second buckets in a deque (max 3600 = 1 hour).
    Every STATS_INTERVAL seconds, flush() writes one JSON line to the stats
    file covering three windows: 5 min, 15 min, 60 min.

    Output fields per window:
      rx       – lines received from conntrack
      tx       – lines written to the log
      dm       – lines dropped (management-IP filter)
      ds       – lines dropped (other / skip)
      rx_s     – average receive rate (lines/sec)
      tx_s     – average write rate (lines/sec)
      p_us     – avg parse time per line (µs)
      w_us     – avg write+flush time per line (µs)
      wait_us  – avg pipe-wait time per line (µs) ← KEY bottleneck indicator

    Interpretation guide
    --------------------
    wait_us ≈ 0, rx_s consistently high  →  Python processing is the bottleneck
    p_us or w_us >> wait_us              →  the respective parse/write step is slow
    rx_s << actual connection rate       →  kernel netlink buffer dropping events
                                            before Python ever sees them
    """

    _WINDOWS = [("5m", 300), ("15m", 900), ("60m", 3600)]

    def __init__(self):
        self._q = collections.deque(maxlen=3600)
        self._cur_sec = int(time.monotonic())
        self._cur = _Bucket()
        self._last_flush_t = time.monotonic()

    def _tick(self):
        now = int(time.monotonic())
        if now == self._cur_sec:
            return
        # gap > 1 when the process was suspended; capped at 3600 to match deque maxlen
        gap = min(now - self._cur_sec, 3600)
        self._q.append(self._cur)
        for _ in range(gap - 1):
            self._q.append(_Bucket())
        self._cur = _Bucket()
        self._cur_sec = now

    def record_drop(self, parse_us, wait_us):
        """Record a line filtered by management-IP check (not written to log)."""
        self._tick()
        b = self._cur
        b.rx += 1
        b.drop_mgmt += 1
        b.parse_us += parse_us
        b.wait_us += wait_us
        b.n += 1

    def record_write(self, parse_us, write_us, wait_us):
        """Record a line successfully written to the log."""
        self._tick()
        b = self._cur
        b.rx += 1
        b.tx += 1
        b.parse_us += parse_us
        b.write_us += write_us
        b.wait_us += wait_us
        b.n += 1

    def _window_stats(self, snapshot):
        all_b = snapshot + [self._cur]
        rx = tx = dm = ds = parse_us = write_us = wait_us = n = 0
        for b in all_b:
            rx       += b.rx
            tx       += b.tx
            dm       += b.drop_mgmt
            ds       += b.drop_skip
            parse_us += b.parse_us
            write_us += b.write_us
            wait_us  += b.wait_us
            n        += b.n
        elapsed = max(len(all_b), 1)
        d = {
            "rx":   rx,
            "tx":   tx,
            "dm":   dm,
            "ds":   ds,
            "rx_s": round(rx / elapsed, 1),
            "tx_s": round(tx / elapsed, 1),
        }
        if n:
            d["p_us"]    = round(parse_us / n)
            d["w_us"]    = round(write_us / n)
            d["wait_us"] = round(wait_us  / n)
        return d

    def due(self):
        return (time.monotonic() - self._last_flush_t) >= STATS_INTERVAL

    def flush(self, fp):
        self._tick()
        snapshot = list(self._q)  # single copy shared across all window calculations
        row = {"ts": now_utc_ms()}
        for name, secs in self._WINDOWS:
            window = snapshot[-secs:] if len(snapshot) > secs else snapshot
            row[name] = self._window_stats(window)
        fp.write(json.dumps(row, separators=(",", ":")) + "\n")
        fp.flush()
        self._last_flush_t = time.monotonic()


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

    vpc_uuid = runtime_env.get("VPC_UUID", "")
    vpc_default_ip = runtime_env.get("VPC_DEFAULT_IP", "")
    if not vpc_uuid:
        return 0

    mgmt_ips = set(
        x
        for x in [
            runtime_env.get("MN_VIP", ""),
            runtime_env.get("MN_IP", ""),
            runtime_env.get("MN_PEER_IP", ""),
            runtime_env.get("MGMT_IP", ""),
        ]
        if x
    )

    lock_fd = acquire_lock()
    if lock_fd is None:
        return 0

    signal.signal(signal.SIGTERM, handle_stop_signal)
    signal.signal(signal.SIGINT, handle_stop_signal)
    signal.signal(signal.SIGHUP, handle_hup_signal)

    # Stats collection is opt-in: set SNAT_LOG_STATS=1 in RUNTIME_ENV_FILE to enable.
    # When disabled the hot loop has zero overhead (no timing calls, no extra file I/O).
    stats = StatsCollector() if runtime_env.get("SNAT_LOG_STATS") in ("1", "true", "yes") else None

    with os.fdopen(lock_fd, "r"):
        log_fp = open(LOG_FILE, "a", buffering=1)
        stats_fp = open(STATS_FILE, "a", buffering=1) if stats is not None else None
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
                # t_iter=None on the first event so startup latency is not recorded as wait_us
                t_iter = None
                for line in _child.stdout:
                    if _stop:
                        break

                    if _reopen:
                        log_fp.close()
                        log_fp = open(LOG_FILE, "a", buffering=1)
                        if stats_fp is not None:
                            stats_fp.close()
                            stats_fp = open(STATS_FILE, "a", buffering=1)
                        _reopen = False

                    if stats is not None:
                        t0 = time.perf_counter()
                        wait_us = int((t0 - t_iter) * 1e6) if t_iter is not None else 0

                        msg = parse_business_record(line, vpc_uuid, vpc_default_ip, mgmt_ips)
                        t1 = time.perf_counter()
                        parse_us = int((t1 - t0) * 1e6)

                        if msg is None:
                            stats.record_drop(parse_us, wait_us)
                        else:
                            log_fp.write(msg + "\n")
                            log_fp.flush()
                            write_us = int((time.perf_counter() - t1) * 1e6)
                            stats.record_write(parse_us, write_us, wait_us)

                        # t_iter is snapped after flush so flush cost doesn't inflate wait_us
                        t_iter = time.perf_counter()

                        if stats.due():
                            stats.flush(stats_fp)
                    else:
                        msg = parse_business_record(line, vpc_uuid, vpc_default_ip, mgmt_ips)
                        if msg is not None:
                            log_fp.write(msg + "\n")
                            log_fp.flush()

            finally:
                if stats is not None:
                    stats.flush(stats_fp)

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
            if stats_fp is not None:
                stats_fp.close()


if __name__ == "__main__":
    sys.exit(run())
