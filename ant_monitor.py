#!/usr/bin/env python3
"""
ANT+ Device Monitor
Detects nearby ANT+ fitness and sensor devices using an ANT+ USB stick.

Hardware required: ANT+ USB dongle (Dynastream ANTUSB-m, Garmin USB-m, etc.)
Software required: openant Python library (pip install openant)

ANT+ operates at 2.457 GHz and is used by:
  - Heart rate monitors, bike power meters, cadence/speed sensors
  - GPS devices, foot pods, muscle oxygen sensors, environment sensors
  - Fitness equipment (treadmills, ellipticals, rowing machines)

Each ANT+ device has a 16-bit device number (set at manufacture or paired)
combined with an 8-bit device type. The combination
(device_number, device_type) is stable and uniquely identifies the device.
Seeing the same device at multiple GPS locations indicates it is following you.
"""

import logging
import threading
import time
from typing import Callable, Dict, Optional, Set

logger = logging.getLogger(__name__)

# ANT+ device type codes → human-readable names
ANT_DEVICE_TYPES: Dict[int, str] = {
    0x01: 'Heart Rate Monitor',
    0x02: 'Bike Speed/Cadence (legacy)',
    0x0B: 'Bike Power Meter',
    0x0C: 'Bike Speed & Cadence',
    0x11: 'Stride Speed/Distance',
    0x1E: 'Foot Pod',
    0x30: 'GPS/Navigation',
    0x60: 'Blood Pressure',
    0x70: 'Muscle Oxygen',
    0x78: 'Bike Speed Sensor',
    0x79: 'Bike Cadence Sensor',
    0x7A: 'Weight Scale',
    0x7B: 'Fitness Equipment',
    0x7C: 'Body Composition',
    0x7D: 'Sports Summary',
    0x80: 'Environment Sensor',
    0x82: 'Geocache',
    0x83: 'Light Electric Vehicle',
    0x84: 'RACQUET',
    0x85: 'Control',
    0x86: 'MuscleO2',
    0x87: 'Exergy (eBike)',
    0x88: 'Drop Bar Bike Controls',
    0x8B: 'Shifting',
    0x8C: 'Suspension',
}

# ANT+ RF frequency offset from 2400 MHz: 57 → 2457 MHz
ANT_RF_FREQ = 57


class ANTMonitor:
    """
    Monitor ANT+ devices using the openant library.

    Calls device_callback(device_id, signal_type, rssi, metadata) for each
    ANT+ device detected. Uses a wildcard "background scan" channel that
    receives broadcasts from any nearby ANT+ device.

    Gracefully disabled when openant is not installed or no USB stick found.
    """

    SIGNAL_TYPE = 'ANT+'

    def __init__(self, config: Dict, device_callback: Callable):
        """
        Args:
            config: 'ant' section from config.json
            device_callback: fn(device_id, signal_type, rssi, metadata)
        """
        self.config = config
        self.device_callback = device_callback
        self.enabled = config.get('enabled', True)
        # How long to listen per scan round before restarting the node
        self.scan_duration: int = config.get('scan_duration', 15)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._node = None
        self.available = False
        if self.enabled:
            self.available = self._check_available()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start the ANT+ monitoring thread. Returns True if started."""
        if not self.enabled or not self.available:
            return False
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name='ANT+-Monitor'
        )
        self._thread.start()
        logger.info("ANT+ monitor started")
        return True

    def stop(self):
        """Stop the monitor."""
        self._running = False
        if self._node:
            try:
                self._node.stop()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=10)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_available(self) -> bool:
        """Check that openant is importable (USB stick check is deferred to start)."""
        try:
            import ant.easy.node  # noqa: F401
            return True
        except ImportError:
            logger.warning(
                "openant not installed — ANT+ monitoring disabled. "
                "Install with: pip install openant"
            )
            return False
        except Exception as e:
            logger.warning("ANT+ availability check error: %s", e)
            return False

    def _monitor_loop(self):
        """Open an ANT+ wildcard channel and collect device broadcasts."""
        try:
            from ant.easy.node import Node
            from ant.easy.channel import Channel
        except ImportError:
            logger.error("openant disappeared — cannot start ANT+ monitor")
            return

        while self._running:
            seen_this_round: Set[str] = set()
            node = None
            try:
                node = Node()
                self._node = node
                node.start()

                # Open a slave receive channel with wildcard IDs.
                # Extended messaging is needed to recover the transmitting
                # device's channel ID (device number + type) from broadcasts.
                channel = node.new_channel(Channel.Type.BIDIRECTIONAL_RECEIVE)
                channel.set_rf_freq(ANT_RF_FREQ)
                channel.set_search_timeout(Channel.SEARCH_TIMEOUT_INFINITE)
                channel.set_period(8070)           # 4 Hz, covers most devices
                channel.set_id(0, 0, 0)            # Wildcard: any device
                channel.enable_extended_messages(True)

                def on_broadcast(data):
                    self._handle_broadcast(data, seen_this_round)

                def on_ext_broadcast(data):
                    self._handle_ext_broadcast(data, seen_this_round)

                channel.on_broadcast_data = on_broadcast
                channel.on_extended_broadcast_data = on_ext_broadcast
                channel.open()

                # Listen for scan_duration seconds, then restart
                deadline = time.time() + self.scan_duration
                while self._running and time.time() < deadline:
                    time.sleep(0.5)

                channel.close()

            except Exception as e:
                logger.error("ANT+ monitor error: %s", e)
                if 'No ANT' in str(e) or 'USB' in str(e) or 'device' in str(e).lower():
                    logger.warning("ANT+ USB stick not found or permission denied")
                    time.sleep(30)
                    continue
            finally:
                if node:
                    try:
                        node.stop()
                    except Exception:
                        pass
                self._node = None

            if self._running:
                time.sleep(1)

    def _handle_ext_broadcast(self, data, seen: Set[str]):
        """
        Handle extended broadcast message which includes channel ID.
        Extended data format (after 8-byte payload):
          byte 9:  channel number
          byte 10: device number LSB
          byte 11: device number MSB
          byte 12: device type
          byte 13: transmission type
        """
        try:
            if len(data) < 14:
                return
            device_num = int.from_bytes(data[9:11], 'little')
            device_type = data[11]
            if device_num == 0:
                return
            self._emit_device(device_num, device_type, seen)
        except Exception as e:
            logger.debug("ANT+ ext broadcast parse error: %s", e)

    def _handle_broadcast(self, data, seen: Set[str]):
        """
        Handle standard broadcast (no channel ID embedded).
        We can only log that something was received; device ID unknown.
        """
        # Without extended messages we cannot reliably identify the device.
        # This is a fallback; _handle_ext_broadcast is preferred.
        pass

    def _emit_device(self, device_num: int, device_type: int, seen: Set[str]):
        """Fire the callback for a decoded ANT+ device."""
        device_id = f"ANT+:{device_num}/{device_type:#04x}"
        if device_id in seen:
            return  # Deduplicate within one scan round
        seen.add(device_id)

        type_name = ANT_DEVICE_TYPES.get(device_type, f"Unknown-{device_type:#04x}")
        self.device_callback(
            device_id=device_id,
            signal_type=self.SIGNAL_TYPE,
            rssi=None,
            metadata={
                'device_number': device_num,
                'device_type_code': device_type,
                'device_type_name': type_name,
            }
        )
