"""
Live Packet Capture Engine for ICDS-H.

Provides real-time network traffic capture using scapy,
extracting features compatible with the TON_IoT model schema.

When scapy/Npcap is not available (common on Windows without Npcap),
the module gracefully falls back and disables live capture.

Configuration (via .env):
    LIVE_CAPTURE_ENABLED=True
    CAPTURE_INTERFACE=Ethernet
    CAPTURE_BPF_FILTER=tcp or udp
    CAPTURE_BATCH_SIZE=10
"""

import asyncio
import time
import threading
from collections import defaultdict
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# SCAPY IMPORT (GRACEFUL FALLBACK)
# ─────────────────────────────────────────────────────────────────────────────

SCAPY_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, conf
    SCAPY_AVAILABLE = True
    print("[PACKET_CAPTURE] Scapy loaded successfully.")
except ImportError:
    print(
        "[PACKET_CAPTURE] Scapy not installed. "
        "Live packet capture disabled. "
        "Install with: pip install scapy"
    )
except Exception as e:
    print(
        f"[PACKET_CAPTURE] Scapy initialization error: {e}. "
        "Npcap may not be installed. "
        "Live packet capture disabled."
    )


# ─────────────────────────────────────────────────────────────────────────────
# CONNECTION TRACKER
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionTracker:
    """
    Tracks active network connections to compute flow-level features.

    Features computed per flow (src_ip:src_port → dst_ip:dst_port):
        - duration (seconds)
        - src_bytes / dst_bytes
        - src_pkts / dst_pkts
        - conn_state_num (simplified)
    """

    def __init__(self, flow_timeout: float = 30.0):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self._lock = threading.Lock()

    def _flow_key(self, pkt):
        """Generate a unique flow key from packet."""
        if IP not in pkt:
            return None

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto

        src_port = 0
        dst_port = 0

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"

    def update(self, pkt):
        """Update flow statistics with new packet."""
        key = self._flow_key(pkt)
        if key is None:
            return None

        now = time.time()
        pkt_len = len(pkt)

        with self._lock:
            if key not in self.flows:
                self.flows[key] = {
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "src_port": pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
                    "dst_port": pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
                    "proto": pkt[IP].proto,
                    "start_time": now,
                    "last_time": now,
                    "src_bytes": 0,
                    "dst_bytes": 0,
                    "src_pkts": 0,
                    "dst_pkts": 0,
                    "tcp_flags": set(),
                }

            flow = self.flows[key]
            flow["last_time"] = now
            flow["src_bytes"] += pkt_len
            flow["src_pkts"] += 1

            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags:
                    flow["tcp_flags"].add(str(flags))

            return key

    def get_completed_flows(self):
        """Return flows that have timed out (completed)."""
        now = time.time()
        completed = []

        with self._lock:
            expired_keys = [
                k for k, v in self.flows.items()
                if now - v["last_time"] > self.flow_timeout
            ]

            for key in expired_keys:
                flow = self.flows.pop(key)
                duration = flow["last_time"] - flow["start_time"]

                # Map TCP flags to a simplified conn_state number
                flags = flow.get("tcp_flags", set())
                conn_state = 0
                if "S" in flags and "A" in flags:
                    conn_state = 4  # Established
                elif "S" in flags:
                    conn_state = 1  # SYN sent
                elif "R" in flags:
                    conn_state = 5  # Reset

                proto_map = {6: "tcp", 17: "udp", 1: "icmp"}

                completed.append({
                    "src_ip": flow["src_ip"],
                    "dst_ip": flow["dst_ip"],
                    "src_port": flow["src_port"],
                    "dst_port": flow["dst_port"],
                    "proto": proto_map.get(flow["proto"], str(flow["proto"])),
                    "duration": round(duration, 3),
                    "src_bytes": flow["src_bytes"],
                    "dst_bytes": flow["dst_bytes"],
                    "src_pkts": flow["src_pkts"],
                    "dst_pkts": flow["dst_pkts"],
                    "conn_state_num": conn_state,
                })

        return completed

    def force_flush_active(self):
        """Force-flush all active flows (for batch processing)."""
        with self._lock:
            flushed = []
            now = time.time()

            for key, flow in list(self.flows.items()):
                duration = now - flow["start_time"]

                flags = flow.get("tcp_flags", set())
                conn_state = 0
                if "S" in flags and "A" in flags:
                    conn_state = 4
                elif "S" in flags:
                    conn_state = 1

                proto_map = {6: "tcp", 17: "udp", 1: "icmp"}

                flushed.append({
                    "src_ip": flow["src_ip"],
                    "dst_ip": flow["dst_ip"],
                    "src_port": flow["src_port"],
                    "dst_port": flow["dst_port"],
                    "proto": proto_map.get(flow["proto"], str(flow["proto"])),
                    "duration": round(duration, 3),
                    "src_bytes": flow["src_bytes"],
                    "dst_bytes": flow["dst_bytes"],
                    "src_pkts": flow["src_pkts"],
                    "dst_pkts": flow["dst_pkts"],
                    "conn_state_num": conn_state,
                })

            self.flows.clear()
            return flushed


# ─────────────────────────────────────────────────────────────────────────────
# PACKET CAPTURE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class PacketCaptureEngine:
    """
    Real-time packet capture engine.

    Captures live network traffic, tracks flows, and produces
    feature dictionaries compatible with the TON_IoT MLP model.
    """

    def __init__(
        self,
        interface: str = "Ethernet",
        bpf_filter: str = "tcp or udp",
        batch_size: int = 10,
        flow_timeout: float = 5.0,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.batch_size = batch_size
        self.tracker = ConnectionTracker(flow_timeout=flow_timeout)
        self._packet_queue = asyncio.Queue()
        self._running = False
        self._capture_thread = None
        self._stats = {
            "packets_captured": 0,
            "flows_completed": 0,
            "events_produced": 0,
            "errors": 0,
        }

    def _packet_callback(self, pkt):
        """Callback for each captured packet."""
        if IP not in pkt:
            return

        try:
            self.tracker.update(pkt)
            self._stats["packets_captured"] += 1
        except Exception as e:
            self._stats["errors"] += 1

    def _capture_loop(self):
        """Background thread for packet capture."""
        print(
            f"[PACKET_CAPTURE] Starting capture on interface: {self.interface} "
            f"with filter: {self.bpf_filter}"
        )

        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            print(
                "[PACKET_CAPTURE] ERROR: Insufficient permissions. "
                "Run as Administrator for live capture."
            )
        except OSError as e:
            if "Npcap" in str(e) or "pcap" in str(e).lower():
                print(
                    "[PACKET_CAPTURE] ERROR: Npcap not found. "
                    "Install from https://npcap.com/ for live capture."
                )
            else:
                print(f"[PACKET_CAPTURE] OS Error: {e}")
        except Exception as e:
            print(f"[PACKET_CAPTURE] Capture error: {e}")
        finally:
            print("[PACKET_CAPTURE] Capture thread stopped.")

    async def start(self):
        """Start the packet capture engine."""
        if not SCAPY_AVAILABLE:
            print("[PACKET_CAPTURE] Scapy not available. Cannot start capture.")
            return False

        self._running = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="PacketCaptureThread",
        )
        self._capture_thread.start()
        print("[PACKET_CAPTURE] Engine started.")
        return True

    def stop(self):
        """Stop the packet capture engine."""
        self._running = False
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)
        print("[PACKET_CAPTURE] Engine stopped.")

    async def get_events(self) -> list:
        """
        Get completed flow events formatted for the MLP pipeline.

        Returns a list of event dicts with raw_features matching
        the TON_IoT schema.
        """
        # Get completed flows
        events = self.tracker.get_completed_flows()

        # If not enough completed flows, force-flush active ones
        if len(events) < self.batch_size:
            flushed = self.tracker.force_flush_active()
            events.extend(flushed)

        self._stats["flows_completed"] += len(events)

        # Format as raw_features for the MLP pipeline
        formatted = []
        for flow in events:
            raw_features = {
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "proto": flow["proto"],
                "duration": flow["duration"],
                "src_bytes": flow["src_bytes"],
                "dst_bytes": flow["dst_bytes"],
                "src_pkts": flow["src_pkts"],
                "dst_pkts": flow["dst_pkts"],
                "conn_state_num": flow["conn_state_num"],
            }

            formatted.append({
                "raw_features": raw_features,
                "dataset": "LIVE_CAPTURE",
                "input_source": "LIVE_NETWORK",
                "timestamp": datetime.utcnow().isoformat(),
            })

        self._stats["events_produced"] += len(formatted)
        return formatted

    def get_stats(self) -> dict:
        """Return capture statistics."""
        return dict(self._stats)

    @property
    def is_running(self) -> bool:
        return self._running and self._capture_thread and self._capture_thread.is_alive()


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

capture_engine = PacketCaptureEngine()
