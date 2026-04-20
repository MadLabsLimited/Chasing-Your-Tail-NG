#!/usr/bin/env python3
"""
Multi-Signal Following Detection System for CYT
===============================================
Orchestrates TPMS, Bluetooth/BLE, ANT+, and Meshtastic monitors into
a unified real-time following detection engine.

Detection strategy mirrors the Wi-Fi probe tracking in chasing_your_tail.py:
  - Four sliding 5-minute time windows (recent / medium / old / oldest)
  - A device reappearing across consecutive windows → TIME PERSISTENCE alert
  - The same device appearing at two or more distinct GPS locations → FOLLOWING alert
  - Full SurveillanceDetector analysis on demand for persistence scoring

Usage:
  python3 signal_monitor.py                  # Monitor all signals
  python3 signal_monitor.py --tpms           # TPMS only
  python3 signal_monitor.py --bluetooth      # Bluetooth/BLE only
  python3 signal_monitor.py --ant            # ANT+ only
  python3 signal_monitor.py --meshtastic     # Meshtastic/LoRa only
  python3 signal_monitor.py --duration 3600  # Run for 1 hour then exit
  python3 signal_monitor.py --report         # Generate report on exit
"""

import argparse
import json
import logging
import os
import pathlib
import signal as os_signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

from surveillance_detector import SurveillanceDetector
from gps_tracker import GPSTracker
from tpms_monitor import TPMSMonitor
from bluetooth_monitor import BluetoothMonitor
from ant_monitor import ANTMonitor
from meshtastic_monitor import MeshtasticMonitor

logger = logging.getLogger(__name__)

SIGNAL_LOG_DIR = pathlib.Path('./signal_logs')
SIGNAL_REPORT_DIR = pathlib.Path('./surveillance_reports')

# Minimum appearances across windows before a time-persistence alert fires
MIN_PERSISTENCE_APPEARANCES = 2


# ---------------------------------------------------------------------------
# Time-window tracker
# ---------------------------------------------------------------------------

class SignalTimeWindows:
    """
    Sliding 5-minute time windows for multi-signal device tracking.

    Structure mirrors SecureTimeWindows in secure_database.py:
      recent  = devices seen in the last 5 minutes
      medium  = devices seen 5-10 minutes ago
      old     = devices seen 10-15 minutes ago
      oldest  = devices seen 15-20 minutes ago

    Keyed by (signal_type, device_id) so each protocol family is
    tracked independently — a BLE device and a TPMS device with
    the same numeric ID do not interfere.
    """

    WINDOW_MINUTES = 5

    def __init__(self):
        self._recent:  Set[tuple] = set()
        self._medium:  Set[tuple] = set()
        self._old:     Set[tuple] = set()
        self._oldest:  Set[tuple] = set()
        self._lock = threading.Lock()

    def add(self, device_id: str, signal_type: str):
        """Record a device sighting in the current window."""
        key = (signal_type, device_id)
        with self._lock:
            self._recent.add(key)

    def previous_windows(self, device_id: str, signal_type: str) -> List[str]:
        """Return names of older windows in which this device was seen."""
        key = (signal_type, device_id)
        found = []
        with self._lock:
            if key in self._medium:
                found.append('5-10 min ago')
            if key in self._old:
                found.append('10-15 min ago')
            if key in self._oldest:
                found.append('15-20 min ago')
        return found

    def rotate(self):
        """
        Advance the windows by one slot (call every WINDOW_MINUTES minutes).
        oldest ← old ← medium ← recent ← (empty)
        """
        with self._lock:
            self._oldest = self._old
            self._old    = self._medium
            self._medium = self._recent
            self._recent = set()

    def snapshot(self) -> Dict[str, int]:
        """Return a {window_name: count} summary for status display."""
        with self._lock:
            return {
                'recent':  len(self._recent),
                'medium':  len(self._medium),
                'old':     len(self._old),
                'oldest':  len(self._oldest),
            }


# ---------------------------------------------------------------------------
# Sighting record
# ---------------------------------------------------------------------------

class _Sighting:
    """Lightweight record of one device detection."""
    __slots__ = ('timestamp', 'location', 'signal_type', 'rssi', 'metadata')

    def __init__(self, timestamp: float, location: str,
                 signal_type: str, rssi: Optional[float], metadata: Dict):
        self.timestamp   = timestamp
        self.location    = location
        self.signal_type = signal_type
        self.rssi        = rssi
        self.metadata    = metadata


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class SignalMonitor:
    """
    Multi-signal following detection orchestrator.

    Integrates TPMS, Bluetooth, ANT+, and Meshtastic monitors into one
    unified detection engine that shares the same sliding-window algorithm
    and SurveillanceDetector used by the Wi-Fi probe tracker.
    """

    def __init__(self, config: Dict, alert_callback: Optional[Callable] = None):
        """
        Args:
            config:         Full CYT config dict (must contain a 'signals' key)
            alert_callback: Optional fn(message: str) called on each alert —
                            use this hook to push messages to the GUI log.
        """
        self.config = config
        self.alert_callback = alert_callback
        self.sig_cfg = config.get('signals', {})

        # GPS tracking — callers update this via set_gps_location()
        self.gps_tracker = GPSTracker(config)
        self.current_location: str = 'unknown'

        # SurveillanceDetector for full batch analysis / report generation
        self.detector = SurveillanceDetector(config)

        # Sliding time windows
        self.windows = SignalTimeWindows()

        # Per-device full sighting history
        self._history: Dict[str, List[_Sighting]] = defaultdict(list)
        self._history_lock = threading.Lock()

        # Track which location-count alerts have already fired to avoid spam
        self._following_alerted: Set[str] = set()

        # Running statistics
        self.stats: Dict[str, int] = {
            'total_sightings':  0,
            'unique_devices':   0,
            'alerts_generated': 0,
        }
        self._stats_lock = threading.Lock()
        self._start_time = time.time()

        # Signal monitors
        self._monitors = self._build_monitors()

        # Background threads
        self._running = False
        self._rotation_thread: Optional[threading.Thread] = None
        self._log_file = None

        # Ensure output directories exist
        SIGNAL_LOG_DIR.mkdir(parents=True, exist_ok=True)
        SIGNAL_REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def _build_monitors(self) -> List:
        monitors = []
        cb = self._on_device_seen

        for name, cls in [
            ('tpms',        TPMSMonitor),
            ('bluetooth',   BluetoothMonitor),
            ('ant',         ANTMonitor),
            ('meshtastic',  MeshtasticMonitor),
        ]:
            cfg = self.sig_cfg.get(name, {})
            if cfg.get('enabled', True):
                monitors.append(cls(cfg, cb))

        return monitors

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def set_gps_location(self, latitude: float, longitude: float,
                         altitude: Optional[float] = None):
        """
        Update the current GPS location used for following detection.
        Call this whenever a new GPS fix is available.
        """
        self.current_location = self.gps_tracker.add_gps_reading(
            latitude, longitude, altitude
        )

    def start(self) -> List[str]:
        """
        Start all configured signal monitors.
        Returns the names of monitors that actually started.
        """
        self._running = True

        # Open session log
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_path = SIGNAL_LOG_DIR / f'signal_monitor_{ts}.log'
        self._log_file = open(log_path, 'w', buffering=1)
        self._log_file.write(
            f"CYT Signal Monitor session started {datetime.now()}\n"
            f"{'=' * 60}\n\n"
        )

        # Start window rotation thread
        self._rotation_thread = threading.Thread(
            target=self._rotation_loop, daemon=True, name='Signal-Window-Rotator'
        )
        self._rotation_thread.start()

        # Start individual signal monitors
        started = []
        for monitor in self._monitors:
            name = type(monitor).__name__.replace('Monitor', '')
            if monitor.start():
                started.append(name)
            elif not monitor.available:
                logger.info(
                    "%s not available — hardware or library missing", name
                )

        if not started:
            logger.warning(
                "No signal monitors started. "
                "See README for hardware/software requirements."
            )

        return started

    def stop(self):
        """Stop all monitors and flush the session log."""
        self._running = False
        for monitor in self._monitors:
            try:
                monitor.stop()
            except Exception:
                pass
        if self._rotation_thread:
            self._rotation_thread.join(timeout=5)
        if self._log_file:
            self._write_session_summary()
            try:
                self._log_file.close()
            except Exception:
                pass

    def generate_report(self) -> str:
        """
        Run the SurveillanceDetector on all collected sightings and write
        a Markdown report. Returns the report text.
        """
        suspicious = self.detector.analyze_surveillance_patterns()

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = SIGNAL_REPORT_DIR / f'signal_report_{ts}.md'

        elapsed_min = (time.time() - self._start_time) / 60.0

        # Signal-type breakdown
        type_counts: Dict[str, int] = defaultdict(int)
        with self._history_lock:
            for sightings in self._history.values():
                for s in sightings:
                    type_counts[s.signal_type] += 1

        lines = [
            "# Signal Following Detection Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Session Statistics",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Duration | {elapsed_min:.1f} minutes |",
            f"| Total sightings | {self.stats['total_sightings']} |",
            f"| Unique devices | {self.stats['unique_devices']} |",
            f"| Alerts generated | {self.stats['alerts_generated']} |",
            "",
            "## Signal Type Breakdown",
        ]
        for sig_type, count in sorted(type_counts.items()):
            lines.append(f"- **{sig_type}**: {count} sightings")

        lines += ["", "## Suspicious Devices"]

        if not suspicious:
            lines.append(
                "_No devices met the threshold for persistent following behaviour._"
            )
        else:
            for dev in sorted(
                suspicious, key=lambda d: d.persistence_score, reverse=True
            ):
                sig_type = (
                    dev.appearances[0].device_type
                    if dev.appearances else 'Unknown'
                )
                threat = (
                    'CRITICAL' if dev.persistence_score >= 0.9 else
                    'HIGH'     if dev.persistence_score >= 0.75 else
                    'MODERATE' if dev.persistence_score >= 0.6 else
                    'LOW'
                )
                lines += [
                    "",
                    f"### {dev.mac}",
                    f"- **Threat level:** {threat}",
                    f"- **Signal type:** {sig_type}",
                    f"- **Persistence score:** {dev.persistence_score:.2f} / 1.00",
                    f"- **Appearances:** {dev.total_appearances}",
                    f"- **Locations seen:** {len(dev.locations_seen)}",
                    f"- **First seen:** {dev.first_seen.strftime('%H:%M:%S')}",
                    f"- **Last seen:** {dev.last_seen.strftime('%H:%M:%S')}",
                    f"- **Reasons:** {'; '.join(dev.reasons)}",
                ]

        report_text = '\n'.join(lines)
        with open(report_path, 'w') as f:
            f.write(report_text)

        logger.info("Signal report written to %s", report_path)
        return report_text

    def status_line(self) -> str:
        """Return a one-line status string suitable for terminal display."""
        elapsed = (time.time() - self._start_time) / 60.0
        snap = self.windows.snapshot()
        return (
            f"[Signal] {elapsed:.1f}min | "
            f"Devices: {self.stats['unique_devices']} | "
            f"Sightings: {self.stats['total_sightings']} | "
            f"Alerts: {self.stats['alerts_generated']} | "
            f"Window: {snap['recent']} recent / {snap['medium']} medium"
        )

    # ------------------------------------------------------------------
    # Core detection callback
    # ------------------------------------------------------------------

    def _on_device_seen(self, device_id: str, signal_type: str,
                        rssi: Optional[float], metadata: Dict):
        """
        Called (thread-safely) by every signal monitor when a device is detected.

        1. Check time-window persistence
        2. Record sighting
        3. Check GPS-location following
        4. Feed SurveillanceDetector
        """
        timestamp = time.time()
        location = self.current_location

        # ── 1. Time-window persistence check (before adding to current window)
        prev_windows = self.windows.previous_windows(device_id, signal_type)

        # ── 2. Add to current window and history
        self.windows.add(device_id, signal_type)

        sighting = _Sighting(timestamp, location, signal_type, rssi, metadata)
        with self._history_lock:
            self._history[device_id].append(sighting)
            history_copy = list(self._history[device_id])

        with self._stats_lock:
            self.stats['total_sightings'] += 1
            self.stats['unique_devices'] = len(self._history)

        # ── 3. Feed surveillance detector for batch analysis
        self.detector.add_device_appearance(
            mac=device_id,
            timestamp=timestamp,
            location_id=location,
            ssids_probed=[],
            signal_strength=rssi,
            device_type=signal_type,
        )

        # ── 4. Real-time time-persistence alert
        if prev_windows:
            self._alert_time_persistence(
                device_id, signal_type, prev_windows, metadata, history_copy
            )

        # ── 5. Real-time GPS following alert
        unique_locs = {
            s.location for s in history_copy
            if s.location and s.location != 'unknown'
        }
        if len(unique_locs) >= 2:
            self._alert_following(
                device_id, signal_type, unique_locs, history_copy, metadata
            )

    # ------------------------------------------------------------------
    # Alert generation
    # ------------------------------------------------------------------

    def _alert_time_persistence(self, device_id: str, signal_type: str,
                                 prev_windows: List[str], metadata: Dict,
                                 history: List[_Sighting]):
        total = len(history)
        span_min = (history[-1].timestamp - history[0].timestamp) / 60.0
        label = self._device_label(device_id, signal_type, metadata)
        ts = datetime.now().strftime('%H:%M:%S')
        msg = (
            f"[{ts}] TIME PERSISTENCE [{signal_type}]\n"
            f"  Device : {label}\n"
            f"  Previously seen: {', '.join(prev_windows)}\n"
            f"  Total appearances: {total} over {span_min:.1f} min\n"
            f"  This device has been near you continuously"
        )
        self._emit_alert(msg)

    def _alert_following(self, device_id: str, signal_type: str,
                          locations: Set[str], history: List[_Sighting],
                          metadata: Dict):
        """Fire once per unique location count reached."""
        alert_key = f"{device_id}:locs:{len(locations)}"
        if alert_key in self._following_alerted:
            return
        self._following_alerted.add(alert_key)

        label = self._device_label(device_id, signal_type, metadata)
        first_ts = datetime.fromtimestamp(history[0].timestamp).strftime('%H:%M:%S')
        ts = datetime.now().strftime('%H:%M:%S')
        span_min = (history[-1].timestamp - history[0].timestamp) / 60.0

        msg = (
            f"[{ts}] *** FOLLOWING DETECTED [{signal_type}] ***\n"
            f"  Device  : {label}\n"
            f"  Seen at : {len(locations)} different GPS locations\n"
            f"  First seen : {first_ts}\n"
            f"  Duration   : {span_min:.1f} minutes\n"
            f"  Appearances: {len(history)}\n"
            f"  ACTION: This device may be physically following you!"
        )
        self._emit_alert(msg)

    def _emit_alert(self, message: str):
        """Print, log, and optionally forward alert to the GUI callback."""
        with self._stats_lock:
            self.stats['alerts_generated'] += 1
        print(f"\n{message}")
        if self._log_file:
            try:
                self._log_file.write(message + '\n\n')
            except Exception:
                pass
        if self.alert_callback:
            try:
                self.alert_callback(message)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _device_label(device_id: str, signal_type: str, metadata: Dict) -> str:
        """Build a human-friendly device label with any available metadata."""
        name = (
            metadata.get('name') or
            metadata.get('node_name') or
            metadata.get('protocol') or
            metadata.get('device_type_name', '')
        )
        if name and name not in ('Unknown', ''):
            return f"{device_id} ({name})"
        if signal_type == 'TPMS':
            p = metadata.get('pressure_kpa')
            if p:
                return f"{device_id} ({p:.0f} kPa)"
        return device_id

    def _rotation_loop(self):
        """Rotate time windows every WINDOW_MINUTES minutes."""
        window_secs = SignalTimeWindows.WINDOW_MINUTES * 60
        while self._running:
            # Sleep in 1-second ticks for responsive shutdown
            for _ in range(window_secs):
                if not self._running:
                    return
                time.sleep(1)
            self.windows.rotate()
            logger.debug("Signal time windows rotated")

    def _write_session_summary(self):
        if not self._log_file:
            return
        elapsed = (time.time() - self._start_time) / 60.0
        self._log_file.write(
            f"\n{'=' * 60}\n"
            f"SESSION SUMMARY\n"
            f"Duration        : {elapsed:.1f} min\n"
            f"Total sightings : {self.stats['total_sightings']}\n"
            f"Unique devices  : {self.stats['unique_devices']}\n"
            f"Alerts generated: {self.stats['alerts_generated']}\n"
        )


# ---------------------------------------------------------------------------
# Command-line entry point
# ---------------------------------------------------------------------------

def _load_config(path: str) -> Dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning("Config file not found: %s — using defaults", path)
        return {}


def main():
    parser = argparse.ArgumentParser(
        description='CYT Multi-Signal Following Detection (TPMS, BT, ANT+, Meshtastic)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--config', default='config.json', metavar='FILE',
                        help='CYT config file (default: config.json)')
    parser.add_argument('--tpms',        action='store_true', help='Enable TPMS only')
    parser.add_argument('--bluetooth',   action='store_true', help='Enable Bluetooth/BLE only')
    parser.add_argument('--ant',         action='store_true', help='Enable ANT+ only')
    parser.add_argument('--meshtastic',  action='store_true', help='Enable Meshtastic/LoRa only')
    parser.add_argument('--duration',    type=int, default=0, metavar='SECONDS',
                        help='Run for N seconds then exit (default: run forever)')
    parser.add_argument('--report',      action='store_true',
                        help='Generate persistence report on exit')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    pathlib.Path('analysis_logs').mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler('analysis_logs/signal_monitor.log'),
            logging.StreamHandler(),
        ]
    )

    config = _load_config(args.config)

    # If specific signal types were requested, disable the rest
    if any([args.tpms, args.bluetooth, args.ant, args.meshtastic]):
        sig = config.setdefault('signals', {})
        sig.setdefault('tpms',       {})['enabled'] = args.tpms
        sig.setdefault('bluetooth',  {})['enabled'] = args.bluetooth
        sig.setdefault('ant',        {})['enabled'] = args.ant
        sig.setdefault('meshtastic', {})['enabled'] = args.meshtastic

    monitor = SignalMonitor(config)

    def _shutdown(signum, frame):
        print("\n\nShutting down signal monitor…")
        monitor.stop()
        if args.report:
            print(monitor.generate_report())
        sys.exit(0)

    os_signal.signal(os_signal.SIGINT,  _shutdown)
    os_signal.signal(os_signal.SIGTERM, _shutdown)

    print("CYT Multi-Signal Following Detection")
    print("=" * 40)
    started = monitor.start()

    if started:
        print(f"Active monitors: {', '.join(started)}")
        print("Ctrl+C to stop\n")
    else:
        print("WARNING: No monitors started. Hardware/library requirements:")
        print("  TPMS        — RTL-SDR dongle + sudo apt install rtl-433")
        print("  Bluetooth   — BT adapter   + sudo apt install bluez")
        print("  ANT+        — ANT+ USB     + pip install openant")
        print("  Meshtastic  — LoRa device  + pip install meshtastic pypubsub")

    end_time = (time.time() + args.duration) if args.duration > 0 else float('inf')
    try:
        while time.time() < end_time:
            print(f"\r{monitor.status_line()}", end='', flush=True)
            time.sleep(5)
    except KeyboardInterrupt:
        pass

    print()
    monitor.stop()
    if args.report or monitor.stats['alerts_generated'] > 0:
        print(monitor.generate_report())


if __name__ == '__main__':
    main()
