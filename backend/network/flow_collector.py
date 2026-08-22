"""
CYPHEX — Network Flow Collector

Reads current network connections from the OS using:
  1. `ss` (Linux — fastest)
  2. `netstat` (macOS/Linux fallback)
  3. `/proc/net/tcp` + `/proc/net/udp` (Linux raw — no root needed)

Returns a list of FlowObservation objects that can be aggregated
into DeviceBehaviourWindow records for the NetworkBehavioralGenome.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Optional

from backend.network.models import (
    DeviceBehaviourWindow,
    FlowObservation,
)

# /proc/net/tcp6 and /proc/net/udp state codes → human readable
_PROC_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1",  "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",      "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN",     "0B": "CLOSING",
}

CLEARTEXT_PORTS = {21, 23, 25, 80, 110, 143, 8080, 8888}
DNS_PORT = 53


def _hex_to_ip_port(hex_addr: str) -> tuple[str, int]:
    """Parse /proc/net/tcp hex address 'AABBCCDD:PPPP' → ('D.C.B.A', port)."""
    try:
        ip_hex, port_hex = hex_addr.split(":")
        # Little-endian byte order
        ip_bytes = bytes.fromhex(ip_hex)[::-1]
        ip = ".".join(str(b) for b in ip_bytes)
        port = int(port_hex, 16)
        return ip, port
    except Exception:
        return "0.0.0.0", 0


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ── Collection strategies ─────────────────────────────────────────────────────

async def collect_flows() -> list[FlowObservation]:
    """
    Collect current network flows using the best available method.
    Returns a list of FlowObservation objects (one per active connection).
    """
    if shutil.which("ss") and sys.platform != "darwin":
        return await _collect_via_ss()
    if shutil.which("netstat"):
        return await _collect_via_netstat()
    if sys.platform.startswith("linux"):
        return _collect_via_proc()
    return []


async def _collect_via_ss() -> list[FlowObservation]:
    """Linux `ss -tunap` — fastest, most complete."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ss", "-tunap", "--no-header",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return _parse_ss(stdout.decode(errors="replace"))
    except Exception:
        return []


def _parse_ss(output: str) -> list[FlowObservation]:
    """
    Parse `ss -tunap` output.
    Columns: Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]
    """
    flows = []
    now = datetime.utcnow().isoformat()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = parts[0].lower()    # tcp | udp
        state = parts[1]
        local = parts[4]
        peer  = parts[5]

        if peer in ("*:*", "-"):
            continue  # Listening / unconnected

        try:
            local_ip, local_port = _split_addr(local)
            peer_ip, peer_port   = _split_addr(peer)
        except Exception:
            continue

        pid, proc_name = _extract_pid_process(parts)

        flows.append(FlowObservation(
            src_ip=local_ip,
            dst_ip=peer_ip,
            src_port=local_port,
            dst_port=peer_port,
            protocol=proto,
            state=state,
            pid=pid,
            process_name=proc_name,
            observed_at=now,
        ))
    return flows


async def _collect_via_netstat() -> list[FlowObservation]:
    """macOS / Linux / Windows netstat fallback."""
    try:
        if sys.platform == "darwin":
            cmd = ["netstat", "-an", "-f", "inet"]
        elif sys.platform == "win32":
            # -tunap is Linux/GNU-style combined short flags — Windows
            # netstat.exe doesn't understand them and errors out. -ano is
            # its own (unrelated) flag spelling: all connections + listening
            # ports + numeric addresses + owning PID.
            cmd = ["netstat", "-ano"]
        else:
            cmd = ["netstat", "-tunap"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        text = stdout.decode(errors="replace")
        return _parse_netstat_windows(text) if sys.platform == "win32" else _parse_netstat(text)
    except Exception:
        return []


def _parse_netstat(output: str) -> list[FlowObservation]:
    """Parse netstat -an output (both macOS and Linux formats)."""
    flows = []
    now = datetime.utcnow().isoformat()
    for line in output.splitlines():
        # Match lines like: tcp   0   0  192.168.1.10:22   192.168.1.5:54321  ESTABLISHED
        # or macOS:          tcp4       0      0  192.168.1.10.22   192.168.1.5.54321 ESTABLISHED
        m = re.match(
            r"(tcp|udp)[46]?\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+(\w+)",
            line.strip(), re.I
        )
        if not m:
            continue
        proto = m.group(1).lower()
        local_raw = m.group(2)
        peer_raw  = m.group(3)
        state     = m.group(4)

        if peer_raw in ("*.*", "*:*", "0.0.0.0:*", ":::*"):
            continue

        try:
            local_ip, local_port = _split_addr(local_raw)
            peer_ip, peer_port   = _split_addr(peer_raw)
        except Exception:
            continue

        flows.append(FlowObservation(
            src_ip=local_ip,
            dst_ip=peer_ip,
            src_port=local_port,
            dst_port=peer_port,
            protocol=proto,
            state=state,
            observed_at=now,
        ))
    return flows


def _parse_netstat_windows(output: str) -> list[FlowObservation]:
    """
    Parse `netstat -ano` output — a different column layout from macOS/Linux
    netstat, not just different flags: no Recv-Q/Send-Q columns, and PID is
    its own trailing column instead of embedded in a Process name field.

        Proto  Local Address          Foreign Address        State           PID
        TCP    192.168.1.5:54321      192.168.1.10:22        ESTABLISHED     1234
        UDP    0.0.0.0:68             *:*                                    812
    """
    flows = []
    now = datetime.utcnow().isoformat()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].lower() not in ("tcp", "udp"):
            continue
        proto = parts[0].lower()
        local_raw = parts[1]
        peer_raw = parts[2]
        # UDP rows have no State column (4 fields: Proto/Local/Foreign/PID);
        # TCP rows have one (5 fields: Proto/Local/Foreign/State/PID).
        if proto == "udp" and len(parts) == 4:
            state, pid = "STATELESS", parts[3]
        elif len(parts) >= 5:
            state, pid = parts[3], parts[4]
        else:
            continue

        if peer_raw in ("*:*", "0.0.0.0:0"):
            continue

        try:
            local_ip, local_port = _split_addr(local_raw)
            peer_ip, peer_port = _split_addr(peer_raw)
        except Exception:
            continue

        flows.append(FlowObservation(
            src_ip=local_ip,
            dst_ip=peer_ip,
            src_port=local_port,
            dst_port=peer_port,
            protocol=proto,
            state=state,
            pid=int(pid) if pid.isdigit() else 0,
            observed_at=now,
        ))
    return flows


def _collect_via_proc() -> list[FlowObservation]:
    """Linux /proc/net/tcp reader — no external tools needed."""
    flows = []
    now = datetime.utcnow().isoformat()
    for proto, path in [("tcp", "/proc/net/tcp"), ("udp", "/proc/net/udp")]:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                lines = f.readlines()[1:]  # skip header
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_ip, local_port = _hex_to_ip_port(parts[1])
                peer_ip, peer_port   = _hex_to_ip_port(parts[2])
                state_code = parts[3].upper()
                state = _PROC_STATES.get(state_code, state_code)
                if peer_ip == "0.0.0.0" and peer_port == 0:
                    continue
                flows.append(FlowObservation(
                    src_ip=local_ip,
                    dst_ip=peer_ip,
                    src_port=local_port,
                    dst_port=peer_port,
                    protocol=proto,
                    state=state,
                    observed_at=now,
                ))
        except Exception:
            continue
    return flows


# ── Aggregation ───────────────────────────────────────────────────────────────

def aggregate_to_window(
    flows: list[FlowObservation],
    device_ip: str,
    window_minutes: int = 5,
    baseline_ips: Optional[set] = None,
) -> DeviceBehaviourWindow:
    """
    Aggregate a list of FlowObservation records (for a single device)
    into a DeviceBehaviourWindow ready for the genome scorer.

    device_ip: the IP of the device we're profiling
    baseline_ips: set of IPs this device normally talks to (for new_destinations)
    """
    # Filter to flows where this device is the source
    my_flows = [f for f in flows if f.src_ip == device_ip]

    now = datetime.utcnow().isoformat()
    w = DeviceBehaviourWindow(
        device_ip=device_ip,
        window_start=now,
        window_end=now,
        window_minutes=window_minutes,
    )

    for f in my_flows:
        w.active_connections += 1
        w.bytes_sent_total += f.bytes_sent
        w.bytes_recv_total += f.bytes_recv
        w.packets_sent_total += f.packets_sent
        w.packets_recv_total += f.packets_recv
        w.unique_remote_ports.add(f.dst_port)
        w.unique_remote_ips.add(f.dst_ip)

        if f.protocol.lower() == "tcp":
            w.tcp_count += 1
            if f.state == "SYN_SENT":
                w.new_connections += 1
            if f.state in ("REFUSED", "RESET"):
                w.refused_connections += 1
        elif f.protocol.lower() == "udp":
            w.udp_count += 1

        if f.dst_port == DNS_PORT:
            w.dns_queries += 1

        if f.dst_port in (80, 443, 8080, 8443):
            w.http_connections += 1

        if f.dst_port in CLEARTEXT_PORTS:
            w.cleartext_connections += 1

        if _is_private(f.dst_ip):
            w.lan_connections += 1
        else:
            w.wan_connections += 1

        if baseline_ips and f.dst_ip not in baseline_ips:
            w.new_destinations += 1

    return w


# ── Helpers ───────────────────────────────────────────────────────────────────

def _split_addr(addr: str) -> tuple[str, int]:
    """
    Split 'ip:port', 'ip.port' (macOS netstat), or '[::1]:port' (IPv6).
    Returns (ip_str, port_int).
    """
    # IPv6 bracket notation
    m = re.match(r"\[(.+)\]:(\d+)", addr)
    if m:
        return m.group(1), int(m.group(2))
    # macOS dotted notation: 192.168.1.1.22  (last component = port)
    if addr.count(".") >= 4:
        parts = addr.rsplit(".", 1)
        return parts[0], int(parts[1])
    # Standard colon notation
    parts = addr.rsplit(":", 1)
    if len(parts) == 2:
        return parts[0], int(parts[1])
    return addr, 0


def _extract_pid_process(parts: list) -> tuple[int, str]:
    """Extract pid and process name from `ss` output (users column)."""
    for part in parts:
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', part)
        if m:
            return int(m.group(2)), m.group(1)
    return 0, ""


# ── Continuous sampling ───────────────────────────────────────────────────────

async def continuous_sample(
    genome,
    interval_s: int = 60,
    alert_callback=None,
):
    """
    Background loop: sample → aggregate → score → alert every interval_s seconds.
    genome: NetworkBehavioralGenome instance (already trained)
    alert_callback: async fn(AnomalyScore) called when anomaly detected
    """
    seen_ips: set = set()

    while True:
        try:
            flows = await collect_flows()

            # Find all source IPs
            source_ips = {f.src_ip for f in flows if _is_private(f.src_ip)}

            for ip in source_ips:
                baseline_ips = genome.device_port_baselines.get(ip, set())
                window = aggregate_to_window(
                    flows, ip,
                    window_minutes=interval_s // 60 or 1,
                    baseline_ips=seen_ips,
                )
                score = genome.score(window)
                if score.is_anomaly and alert_callback:
                    await alert_callback(score)

            # Update seen IPs (rolling baseline of known peers)
            for f in flows:
                seen_ips.add(f.dst_ip)
                if len(seen_ips) > 10_000:
                    seen_ips = set(list(seen_ips)[-5_000:])

        except Exception:
            pass

        await asyncio.sleep(interval_s)
