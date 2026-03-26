"""
CyberShield-X — Live Packet Capture & Anomaly Detection Engine.

Uses Scapy to sniff live network traffic, extracts flow features,
and feeds them into the statistical anomaly detection pipeline.

Graceful fallback: if Scapy is unavailable or interface access is denied,
a realistic traffic simulator is used automatically — ideal for demos.

Environment variables:
  SNIFF_INTERFACE   Network interface to sniff (default: "any")
  SNIFF_FILTER      BPF filter string (default: "ip")
  SIMULATE_TRAFFIC  Set to "1" to force simulation mode
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import random
import socket
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cybershield.ingestion.pcap_sniffer")

SNIFF_INTERFACE  = os.getenv("SNIFF_INTERFACE", "any")
SNIFF_FILTER     = os.getenv("SNIFF_FILTER", "ip")
FORCE_SIMULATE   = os.getenv("SIMULATE_TRAFFIC", "0") == "1"

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 132: "SCTP"}

# ─────────────────────────────────────────
# Feature extraction helpers
# ─────────────────────────────────────────

def _entropy(payload: bytes) -> float:
    """Shannon entropy of a byte sequence (0-8 range)."""
    if not payload:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in payload:
        freq[b] += 1
    n = len(payload)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _extract_event(pkt: Any) -> Optional[Dict[str, Any]]:
    """Extract a NetworkEvent dict from a Scapy packet.

    Returns None if the packet is not an IP packet.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore[import-untyped]

        if IP not in pkt:
            return None

        ip   = pkt[IP]
        proto_num = ip.proto
        proto = PROTO_MAP.get(proto_num, str(proto_num))

        src_ip = ip.src
        dst_ip = ip.dst
        dst_port = 0
        payload_bytes = b""

        if TCP in pkt:
            dst_port = pkt[TCP].dport
            payload_bytes = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            payload_bytes = bytes(pkt[UDP].payload)
        elif ICMP in pkt:
            payload_bytes = bytes(pkt[ICMP].payload)

        size = len(pkt)

        return {
            "event_id":        str(uuid.uuid4()),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "src_ip":          src_ip,
            "dst_ip":          dst_ip,
            "dst_port":        dst_port,
            "protocol":        proto,
            "bytes_sent":      size,
            "bytes_recv":      0,
            "duration_ms":     0,
            "payload_entropy": round(_entropy(payload_bytes[:256]), 3),
        }
    except Exception:
        return None


# ─────────────────────────────────────────
# Traffic Simulator (fallback / demo mode)
# ─────────────────────────────────────────

_ATTACK_TEMPLATES = [
    # (src_ip pattern, dst_ip, dst_port, proto, bytes_sent, payload_entropy, label)
    ("185.220.{}.{}",  "10.0.0.5",   4444,  "TCP",  312,  7.8,  "c2_beacon"),
    ("185.220.{}.{}",  "10.0.0.5",   4444,  "TCP",  290,  7.5,  "c2_beacon"),
    ("203.0.113.{}",   "10.0.0.10",  3389,  "TCP",  80,   0.4,  "brute_force"),
    ("203.0.113.{}",   "10.0.0.10",  22,    "TCP",  64,   0.3,  "brute_force"),
    ("10.1.0.{}",      "10.2.0.{}",  445,   "TCP",  1200, 3.5,  "lateral_movement"),
    ("198.51.100.{}",  "10.0.0.20",  0,     "TCP",  10_500_000, 5.1, "data_exfiltration"),
    ("172.16.0.{}",    "172.17.0.{}", 135,  "TCP",  800,  2.1,  "lateral_movement"),
]

_BENIGN_TEMPLATES = [
    ("10.0.0.{}",   "8.8.8.8",      53,   "UDP", 64,   0.5),
    ("10.0.0.{}",   "1.1.1.1",      53,   "UDP", 64,   0.5),
    ("10.0.0.{}",   "104.26.0.{}",  443,  "TCP", 1400, 4.2),
    ("10.0.0.{}",   "172.217.0.{}", 443,  "TCP", 900,  3.8),
    ("10.0.0.{}",   "192.168.1.1",  80,   "TCP", 600,  2.1),
    ("192.168.1.{}", "10.0.0.{}",   8080, "TCP", 450,  1.9),
]


def _rand_ip_template(tmpl: str) -> str:
    return tmpl.format(random.randint(1, 254), random.randint(1, 254))


def _simulate_packet() -> Dict[str, Any]:
    """Generate a single synthetic network flow event."""
    # 20% chance of an attack-pattern packet for demo purposes
    if random.random() < 0.20:
        t = random.choice(_ATTACK_TEMPLATES)
        src = _rand_ip_template(t[0])
        dst = _rand_ip_template(t[1]) if "{}" in t[1] else t[1]
        return {
            "event_id":        str(uuid.uuid4()),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "src_ip":          src,
            "dst_ip":          dst,
            "dst_port":        t[3 - 1] if False else t[2],   # dst_port is index 2
            "protocol":        t[3],
            "bytes_sent":      t[4],
            "bytes_recv":      0,
            "duration_ms":     random.randint(50, 500),
            "payload_entropy": t[5],
            "_simulated":      True,
            "_label":          t[6],
        }
    else:
        t = random.choice(_BENIGN_TEMPLATES)
        src = _rand_ip_template(t[0])
        dst = _rand_ip_template(t[1]) if "{}" in t[1] else t[1]
        return {
            "event_id":        str(uuid.uuid4()),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "src_ip":          src,
            "dst_ip":          dst,
            "dst_port":        t[2],
            "protocol":        t[3],
            "bytes_sent":      t[4],
            "bytes_recv":      random.randint(200, 1500),
            "duration_ms":     random.randint(10, 200),
            "payload_entropy": t[5],
            "_simulated":      True,
            "_label":          "benign",
        }


# ─────────────────────────────────────────
# Live Packet Sniffer
# ─────────────────────────────────────────

class LivePacketSniffer:
    """Captures live network packets and feeds them to an asyncio queue.

    Automatically falls back to simulated traffic if:
    - Scapy is not installed
    - SIMULATE_TRAFFIC=1 env var is set
    - Interface access is denied (e.g. no root privileges)
    """

    def __init__(
        self,
        event_queue: asyncio.Queue,
        interface: str = SNIFF_INTERFACE,
        bpf_filter: str = SNIFF_FILTER,
        pps: float = 10.0,          # Simulated packets-per-second
    ) -> None:
        self._queue     = event_queue
        self._interface = interface
        self._filter    = bpf_filter
        self._pps       = pps         # used in simulate mode

        self._thread: Optional[threading.Thread] = None
        self._running   = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._simulated = False

        # counters
        self.packets_captured  = 0
        self.packets_per_sec   = 0.0
        self._last_count_ts    = time.time()
        self._last_count       = 0

    # ── public API ─────────────────────────

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Start the sniffer in a background daemon thread."""
        if self._running:
            return
        self._running = True
        self._loop    = loop

        # Try Scapy first
        scapy_ok = self._try_scapy_start()
        if not scapy_ok or FORCE_SIMULATE:
            logger.info("[Sniffer] Starting in SIMULATION mode (Scapy unavailable or SIMULATE_TRAFFIC=1)")
            self._simulated = True
            self._thread = threading.Thread(target=self._simulate_loop, daemon=True)
            self._thread.start()
        else:
            logger.info("[Sniffer] Scapy live capture started on interface=%s filter='%s'", self._interface, self._filter)

    def stop(self) -> None:
        """Signal the sniffer to stop."""
        self._running = False
        logger.info("[Sniffer] Stopped. Total packets captured: %d", self.packets_captured)

    def update_rate(self) -> None:
        """Update packets-per-second rate. Call periodically."""
        now = time.time()
        elapsed = now - self._last_count_ts
        if elapsed >= 1.0:
            delta = self.packets_captured - self._last_count
            self.packets_per_sec = round(delta / elapsed, 1)
            self._last_count    = self.packets_captured
            self._last_count_ts = now

    @property
    def mode(self) -> str:
        return "simulated" if self._simulated else "live"

    # ── internal Scapy capture ──────────────

    def _try_scapy_start(self) -> bool:
        try:
            from scapy.all import sniff  # type: ignore[import-untyped]
            self._thread = threading.Thread(target=self._scapy_loop, daemon=True)
            self._thread.start()
            return True
        except ImportError:
            logger.warning("[Sniffer] Scapy not installed — falling back to simulation.")
            return False
        except Exception as exc:
            logger.warning("[Sniffer] Scapy start failed (%s) — falling back to simulation.", exc)
            return False

    def _scapy_loop(self) -> None:
        from scapy.all import sniff  # type: ignore[import-untyped]
        try:
            iface = None if self._interface == "any" else self._interface
            sniff(
                iface=iface,
                filter=self._filter,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as exc:
            logger.error("[Sniffer] Scapy capture error: %s — switching to simulation.", exc)
            self._simulated = True
            self._simulate_loop()

    def _on_packet(self, pkt: Any) -> None:
        if not self._running:
            return
        event = _extract_event(pkt)
        if event:
            self.packets_captured += 1
            if self._loop and not self._loop.is_closed():
                asyncio.run_coroutine_threadsafe(self._queue.put(event), self._loop)

    # ── simulation loop ────────────────────

    def _simulate_loop(self) -> None:
        """Generate synthetic packets at self._pps packets-per-second."""
        interval = 1.0 / max(self._pps, 0.1)
        while self._running:
            event = _simulate_packet()
            self.packets_captured += 1
            if self._loop and not self._loop.is_closed():
                asyncio.run_coroutine_threadsafe(self._queue.put(event), self._loop)
            time.sleep(interval)


# ─────────────────────────────────────────
# Sniffer Manager (singleton per service)
# ─────────────────────────────────────────

class SnifferManager:
    """Manages a singleton LivePacketSniffer connected to an event queue."""

    def __init__(self) -> None:
        self._queue:   asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._sniffer: Optional[LivePacketSniffer] = None
        self._started  = False
        self._start_ts = 0.0

    @property
    def is_running(self) -> bool:
        return self._started and self._sniffer is not None and self._sniffer._running

    def start(self, loop: asyncio.AbstractEventLoop) -> Dict[str, Any]:
        if self._started:
            return {"status": "already_running", "mode": self._sniffer.mode if self._sniffer else "?"}
        self._sniffer = LivePacketSniffer(event_queue=self._queue)
        self._sniffer.start(loop)
        self._started  = True
        self._start_ts = time.time()
        return {"status": "started", "mode": self._sniffer.mode, "interface": SNIFF_INTERFACE}

    def stop(self) -> Dict[str, Any]:
        if not self._started or not self._sniffer:
            return {"status": "not_running"}
        self._sniffer.stop()
        self._started = False
        captured = self._sniffer.packets_captured
        self._sniffer = None
        return {"status": "stopped", "packets_captured": captured}

    def status(self) -> Dict[str, Any]:
        if not self._started or not self._sniffer:
            return {"running": False}
        self._sniffer.update_rate()
        return {
            "running":           True,
            "mode":              self._sniffer.mode,
            "interface":         SNIFF_INTERFACE,
            "filter":            SNIFF_FILTER,
            "packets_captured":  self._sniffer.packets_captured,
            "packets_per_sec":   self._sniffer.packets_per_sec,
            "uptime_s":          round(time.time() - self._start_ts),
        }

    async def get_event(self, timeout: float = 0.1) -> Optional[Dict[str, Any]]:
        """Pop one event from the queue. Returns None on timeout."""
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
