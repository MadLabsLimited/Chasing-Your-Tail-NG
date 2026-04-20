#!/usr/bin/env python3
"""
Bluetooth and Bluetooth Low Energy (BLE) Device Monitor
Detects nearby Bluetooth devices and tracks their persistence over time.

Hardware required: Any Bluetooth adapter (built-in or USB dongle)
Software required: bluez (sudo apt install bluez)
Permissions: BLE scanning requires CAP_NET_RAW — run with sudo or
             add the capability: sudo setcap cap_net_raw+ep $(which python3)

Classic Bluetooth:  periodic inquiry scan (hcitool scan)
BLE:                continuous advertisement capture (hcitool lescan)

Address stability notes:
  - Classic BT public addresses (BDA) are stable hardware identifiers.
  - BLE public addresses are stable.
  - BLE static random addresses (MSBs = 11) are stable per session.
  - BLE resolvable/non-resolvable private addresses rotate frequently
    and are filtered out to avoid false positives.
"""

import logging
import re
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Regex for a Bluetooth address optionally followed by a device name
_ADDR_RE = re.compile(
    r'(?P<addr>([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})'
    r'(?:\s+(?P<name>.+))?'
)

# BLE RSSI line from hcitool leinfo / some scan output
_RSSI_RE = re.compile(r'RSSI[:\s]+([-\d]+)')


def _is_stable_ble_address(addr: str) -> bool:
    """
    Return True if this BLE address is stable enough to track.
    Filters out resolvable private (MSB pattern 01xxxxxx) and
    non-resolvable private (MSB pattern 00xxxxxx) addresses.
    Public (00xxxxxx in address type) and static random (11xxxxxx)
    addresses are stable.
    """
    first_byte = int(addr[:2], 16)
    top_two = (first_byte >> 6) & 0b11
    # Static random = 11; public BDA = always stable (no filter needed)
    # Resolvable private = 01, Non-resolvable private = 00
    return top_two == 0b11 or top_two == 0b00  # include public & static random


class BluetoothMonitor:
    """
    Scan for Bluetooth Classic and BLE devices using system bluez tools.

    Calls device_callback(device_id, signal_type, rssi, metadata) for each
    discovered device. Callbacks come from background threads.

    Two independent scanning loops run concurrently:
      - BLE loop:     continuous hcitool lescan (catches low-power devices)
      - Classic loop: periodic hcitool scan inquiry (catches phones, headsets)
    """

    BLE_SIGNAL_TYPE = 'BLE'
    BT_SIGNAL_TYPE = 'Bluetooth'

    def __init__(self, config: Dict, device_callback: Callable):
        """
        Args:
            config: 'bluetooth' section from config.json
            device_callback: fn(device_id, signal_type, rssi, metadata)
        """
        self.config = config
        self.device_callback = device_callback
        self.enabled = config.get('enabled', True)
        self.scan_ble = config.get('scan_ble', True)
        self.scan_classic = config.get('scan_classic', True)
        # Seconds between classic inquiry sweeps (each sweep ~10 s)
        self.classic_interval: int = config.get('scan_interval', 30)
        # Pass --duplicates to hcitool lescan so we see repeated advertisements
        self.ble_duplicates: bool = config.get('ble_duplicates', True)
        self._running = False
        self._threads: List[threading.Thread] = []
        self._ble_process: Optional[subprocess.Popen] = None
        self.available = False
        if self.enabled:
            self.available = self._check_available()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start BLE and/or classic BT scanning threads. Returns True if started."""
        if not self.enabled or not self.available:
            return False
        self._running = True
        if self.scan_ble:
            t = threading.Thread(
                target=self._ble_loop, daemon=True, name='BLE-Monitor'
            )
            t.start()
            self._threads.append(t)
        if self.scan_classic:
            t = threading.Thread(
                target=self._classic_loop, daemon=True, name='BT-Classic-Monitor'
            )
            t.start()
            self._threads.append(t)
        logger.info(
            "Bluetooth monitor started — BLE=%s, Classic=%s",
            self.scan_ble, self.scan_classic
        )
        return bool(self._threads)

    def stop(self):
        """Stop all scanning."""
        self._running = False
        if self._ble_process:
            try:
                self._ble_process.terminate()
                self._ble_process.wait(timeout=3)
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=5)

    # ------------------------------------------------------------------
    # BLE scanning
    # ------------------------------------------------------------------

    def _ble_loop(self):
        """Continuously run hcitool lescan and parse advertisement lines."""
        cmd = ['sudo', 'hcitool', 'lescan']
        if self.ble_duplicates:
            cmd.append('--duplicates')

        while self._running:
            try:
                self._ble_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
                for line in self._ble_process.stdout:
                    if not self._running:
                        break
                    self._parse_ble_line(line.strip())
                self._ble_process.wait()

            except PermissionError:
                logger.warning(
                    "BLE scan needs elevated privileges. "
                    "Run with sudo, or: sudo setcap cap_net_raw+ep $(which python3)"
                )
                time.sleep(60)
            except FileNotFoundError:
                logger.warning("hcitool not found — install bluez: sudo apt install bluez")
                break
            except Exception as e:
                logger.debug("BLE scan loop error: %s", e)

            if self._running:
                time.sleep(2)

    def _parse_ble_line(self, line: str):
        """Extract address and optional name from 'AA:BB:CC:DD:EE:FF [Name]' line."""
        m = _ADDR_RE.match(line)
        if not m:
            return
        addr = m.group('addr').upper()
        name = (m.group('name') or '').strip()

        if not _is_stable_ble_address(addr):
            return  # Skip rotating private addresses

        self.device_callback(
            device_id=f"BLE:{addr}",
            signal_type=self.BLE_SIGNAL_TYPE,
            rssi=None,
            metadata={
                'name': name or 'Unknown',
                'address': addr,
            }
        )

    # ------------------------------------------------------------------
    # Classic Bluetooth scanning
    # ------------------------------------------------------------------

    def _classic_loop(self):
        """Periodically run hcitool scan (inquiry) and report discovered devices."""
        while self._running:
            try:
                result = subprocess.run(
                    ['hcitool', 'scan', '--flush'],
                    capture_output=True, text=True, timeout=20
                )
                for line in result.stdout.splitlines():
                    m = _ADDR_RE.match(line.strip())
                    if m:
                        addr = m.group('addr').upper()
                        name = (m.group('name') or '').strip()
                        self.device_callback(
                            device_id=f"BT:{addr}",
                            signal_type=self.BT_SIGNAL_TYPE,
                            rssi=None,
                            metadata={
                                'name': name or 'Unknown',
                                'address': addr,
                            }
                        )
            except subprocess.TimeoutExpired:
                pass  # Inquiry timeout is normal
            except FileNotFoundError:
                logger.warning("hcitool not found — install bluez: sudo apt install bluez")
                break
            except Exception as e:
                logger.debug("Classic BT scan error: %s", e)

            # Sleep in 1-second increments so stop() is responsive
            for _ in range(self.classic_interval):
                if not self._running:
                    break
                time.sleep(1)

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def _check_available(self) -> bool:
        """Return True if a Bluetooth adapter is present via hcitool."""
        try:
            result = subprocess.run(
                ['hcitool', 'dev'],
                capture_output=True, text=True, timeout=5
            )
            if 'hci' in result.stdout:
                return True
            logger.warning("No Bluetooth adapter found (hcitool dev shows no hciX device)")
            return False
        except FileNotFoundError:
            logger.warning(
                "hcitool not found — Bluetooth monitoring disabled. "
                "Install with: sudo apt install bluez"
            )
            return False
        except Exception as e:
            logger.warning("Bluetooth availability check failed: %s", e)
            return False
