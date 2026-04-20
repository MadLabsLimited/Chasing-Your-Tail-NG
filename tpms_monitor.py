#!/usr/bin/env python3
"""
TPMS (Tire Pressure Monitoring System) Signal Monitor
Captures TPMS tire pressure sensor broadcasts from nearby vehicles
using RTL-SDR hardware and the rtl_433 decoder.

Hardware required: RTL-SDR dongle (RTL2832U-based, e.g. NooElec, RTL-SDR Blog)
Software required: rtl_433 (sudo apt install rtl-433)

TPMS sensors transmit a short burst every ~60 seconds while driving,
or whenever tire pressure changes significantly. Each sensor has a
factory-programmed unique ID (28-32 bits) that never changes.
Tracking that ID across locations reveals a vehicle following you.
"""

import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Keywords found in rtl_433 model strings for TPMS devices.
# rtl_433 supports 80+ TPMS protocols; this list catches them all.
TPMS_MODEL_KEYWORDS = [
    'tpms', 'tire', 'schrader', 'jansite', 'citroen',
    'ford', 'renault', 'toyota', 'pmv', 'pressure_pro',
    'ctek', 'truck', 'hyundai', 'honda', 'infiniti',
    'nissan', 'subaru', 'mitsubishi', 'chevrolet', 'dodge',
    'chrysler', 'jeep', 'bmw', 'mercedes', 'audi', 'volkswagen',
    'kia', 'mazda', 'volvo', 'gm', 'gmc', 'buick', 'cadillac',
]


@dataclass
class TPMSDevice:
    """A decoded TPMS tire-pressure sensor reading."""
    device_id: str                   # Normalized unique sensor ID, e.g. "TPMS:0x1a2b3c4d"
    protocol: str                    # Manufacturer/model from rtl_433
    pressure_kpa: Optional[float]    # Tire pressure in kPa
    temperature_c: Optional[float]   # Temperature in °C (if available)
    battery_ok: Optional[bool]       # Battery status (if reported)
    rssi: Optional[float]            # Received signal strength (dBm)
    timestamp: float                 # Unix timestamp of reception


class TPMSMonitor:
    """
    Monitor TPMS tire-pressure sensors using RTL-SDR + rtl_433.

    Calls device_callback(device_id, signal_type, rssi, metadata) whenever
    a TPMS sensor packet is decoded. The callback is invoked from a background
    thread, so callers must be thread-safe.

    Gracefully does nothing when rtl_433 is not installed or the RTL-SDR
    dongle is absent — the rest of the system continues unaffected.
    """

    SIGNAL_TYPE = 'TPMS'

    def __init__(self, config: Dict, device_callback: Callable):
        """
        Args:
            config: 'tpms' section from config.json
            device_callback: fn(device_id, signal_type, rssi, metadata)
        """
        self.config = config
        self.device_callback = device_callback
        self.enabled = config.get('enabled', True)
        # Both North American (315 MHz) and worldwide (433.92 MHz) bands
        self.frequencies: List[str] = config.get('frequencies', ['315M', '433.92M'])
        self.rtl_device_index: int = config.get('rtl_device', 0)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._process: Optional[subprocess.Popen] = None
        self.available = False
        if self.enabled:
            self.available = self._check_available()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start the TPMS monitor background thread. Returns True if started."""
        if not self.enabled or not self.available:
            return False
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name='TPMS-Monitor'
        )
        self._thread.start()
        logger.info("TPMS monitor started — frequencies: %s", self.frequencies)
        return True

    def stop(self):
        """Stop the monitor and clean up."""
        self._running = False
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_available(self) -> bool:
        """Verify rtl_433 binary is on PATH."""
        try:
            subprocess.run(
                ['rtl_433', '-h'],
                capture_output=True, text=True, timeout=3
            )
            return True
        except FileNotFoundError:
            logger.warning(
                "rtl_433 not found — TPMS monitoring disabled. "
                "Install with: sudo apt install rtl-433"
            )
            return False
        except Exception:
            return True  # Binary exists even if timeout/error

    def _monitor_loop(self):
        """Continuously run rtl_433 and parse TPMS packets from its JSON output."""
        freq_args: List[str] = []
        for f in self.frequencies:
            freq_args += ['-f', f]

        cmd = (
            ['rtl_433', '-d', str(self.rtl_device_index)]
            + freq_args
            + [
                '-F', 'json',    # JSON output, one object per line
                '-M', 'level',   # Include RSSI/SNR in output
                '-q',            # Suppress status messages
            ]
        )

        while self._running:
            try:
                self._process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
                for line in self._process.stdout:
                    if not self._running:
                        break
                    self._parse_line(line.strip())
                self._process.wait()
            except FileNotFoundError:
                logger.error("rtl_433 disappeared from PATH — stopping TPMS monitor")
                break
            except Exception as e:
                logger.error("TPMS monitor error: %s", e)

            if self._running:
                time.sleep(3)  # Brief pause before restarting rtl_433

    def _parse_line(self, line: str):
        """Parse one JSON line from rtl_433 and emit a TPMS callback if applicable."""
        if not line.startswith('{'):
            return
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return

        model = data.get('model', '').lower()
        if not any(kw in model for kw in TPMS_MODEL_KEYWORDS):
            return

        # rtl_433 uses various field names for the sensor ID across protocols
        raw_id = data.get('id', data.get('sensor_id', data.get('uid', data.get('code', ''))))
        if not raw_id and raw_id != 0:
            return

        # Normalize to a stable hex string
        if isinstance(raw_id, int):
            device_id = f"TPMS:{raw_id:#010x}"
        else:
            device_id = f"TPMS:{str(raw_id).strip()}"

        # Pressure: prefer kPa, convert bar or PSI if needed
        pressure_kpa: Optional[float] = data.get('pressure_kPa')
        if pressure_kpa is None and 'pressure_bar' in data:
            pressure_kpa = float(data['pressure_bar']) * 100.0
        if pressure_kpa is None and 'pressure_PSI' in data:
            pressure_kpa = float(data['pressure_PSI']) * 6.89476

        self.device_callback(
            device_id=device_id,
            signal_type=self.SIGNAL_TYPE,
            rssi=data.get('rssi'),
            metadata={
                'protocol': data.get('model', 'TPMS'),
                'pressure_kpa': pressure_kpa,
                'temperature_c': data.get('temperature_C'),
                'battery_ok': data.get('battery_ok', data.get('battery', None)),
                'flags': data.get('flags'),
            }
        )
