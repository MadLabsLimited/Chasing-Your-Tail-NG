#!/usr/bin/env python3
"""
Meshtastic / LoRa Mesh Network Monitor
Detects nearby Meshtastic nodes and tracks their persistence over time.

Hardware required: Meshtastic-compatible LoRa device connected via USB or network
  Examples: LILYGO T-Beam, LILYGO T-Echo, Heltec LoRa 32, RAK WisBlock
Software required: meshtastic Python library (pip install meshtastic)
                   pypubsub (pip install pypubsub)

Meshtastic uses LoRa radio (433/868/915/923 MHz depending on region).
Every node broadcasts a NodeInfo packet on power-up and periodically thereafter.
Each node has a stable 32-bit hardware ID displayed as "!hex" (e.g. !a1b2c3d4).
Seeing the same node ID at different GPS locations indicates it may be following you.

Connection modes:
  USB serial: auto-detect or specify serial_port = "/dev/ttyUSB0"
  TCP:        specify tcp_host = "192.168.x.x" (when node runs in WiFi client mode)
"""

import logging
import threading
import time
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)


class MeshtasticMonitor:
    """
    Listen to Meshtastic mesh traffic and report nearby node IDs.

    Calls device_callback(device_id, signal_type, rssi, metadata) for every
    unique Meshtastic node heard. Callbacks come from a background thread.

    Gracefully disabled when the meshtastic library is not installed or
    no Meshtastic device is connected.
    """

    SIGNAL_TYPE = 'Meshtastic'

    def __init__(self, config: Dict, device_callback: Callable):
        """
        Args:
            config: 'meshtastic' section from config.json
            device_callback: fn(device_id, signal_type, rssi, metadata)
        """
        self.config = config
        self.device_callback = device_callback
        self.enabled = config.get('enabled', True)
        # USB serial port path, e.g. '/dev/ttyUSB0'. None = auto-detect.
        self.serial_port: Optional[str] = config.get('serial_port', None)
        # TCP host when node runs in WiFi client mode (e.g. '192.168.1.10')
        self.tcp_host: Optional[str] = config.get('tcp_host', None)
        self.tcp_port: int = config.get('tcp_port', 4403)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._interface = None
        self._sub_handle = None
        self.available = False
        if self.enabled:
            self.available = self._check_available()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start the Meshtastic monitor thread. Returns True if started."""
        if not self.enabled or not self.available:
            return False
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name='Meshtastic-Monitor'
        )
        self._thread.start()
        logger.info("Meshtastic monitor started")
        return True

    def stop(self):
        """Disconnect and stop the monitor."""
        self._running = False
        self._close_interface()
        if self._thread:
            self._thread.join(timeout=10)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_available(self) -> bool:
        """Check that the meshtastic library is importable."""
        try:
            import meshtastic  # noqa: F401
            return True
        except ImportError:
            logger.warning(
                "meshtastic library not installed — Meshtastic monitoring disabled. "
                "Install with: pip install meshtastic"
            )
            return False
        except Exception as e:
            logger.warning("Meshtastic availability check error: %s", e)
            return False

    def _connect(self):
        """Create and return a Meshtastic interface based on config."""
        if self.tcp_host:
            from meshtastic.tcp_interface import TCPInterface
            return TCPInterface(
                hostname=self.tcp_host,
                portNumber=self.tcp_port,
                noProto=False,
            )
        elif self.serial_port:
            from meshtastic.serial_interface import SerialInterface
            return SerialInterface(devPath=self.serial_port)
        else:
            # Auto-detect USB serial
            from meshtastic.serial_interface import SerialInterface
            return SerialInterface()

    def _close_interface(self):
        if self._interface:
            try:
                self._interface.close()
            except Exception:
                pass
            self._interface = None

    def _get_node_name(self, from_id) -> str:
        """Look up long name for a node ID from the interface's node database."""
        try:
            if self._interface and hasattr(self._interface, 'nodes'):
                nodes = self._interface.nodes or {}
                node_info = nodes.get(str(from_id), {})
                user = node_info.get('user', {})
                return user.get('longName') or user.get('shortName') or 'Unknown'
        except Exception:
            pass
        return 'Unknown'

    def _monitor_loop(self):
        """Connect to the Meshtastic device and listen for mesh packets."""
        try:
            from pubsub import pub
        except ImportError:
            logger.warning(
                "pypubsub not installed — Meshtastic monitoring disabled. "
                "Install with: pip install pypubsub"
            )
            return

        while self._running:
            sub_handle = None
            try:
                # Build the receive callback inside the loop so it captures
                # the current self._interface reference correctly.
                def on_receive(packet, interface=None):
                    if not self._running:
                        return
                    try:
                        # fromId is the canonical string like "!a1b2c3d4"
                        from_id = packet.get('fromId') or packet.get('from')
                        if not from_id:
                            return

                        device_id = f"MESH:{from_id}"
                        rssi = packet.get('rxRssi')
                        snr = packet.get('rxSnr')
                        decoded = packet.get('decoded', {})
                        portnum = decoded.get('portnum', 'UNKNOWN_APP')
                        node_name = self._get_node_name(from_id)

                        self.device_callback(
                            device_id=device_id,
                            signal_type=self.SIGNAL_TYPE,
                            rssi=rssi,
                            metadata={
                                'node_name': node_name,
                                'portnum': portnum,
                                'snr': snr,
                                'hop_limit': packet.get('hopLimit'),
                                'channel': packet.get('channel', 0),
                            }
                        )
                    except Exception as e:
                        logger.debug("Meshtastic packet parse error: %s", e)

                pub.subscribe(on_receive, 'meshtastic.receive')
                sub_handle = on_receive

                self._interface = self._connect()
                logger.info(
                    "Connected to Meshtastic device (%s)",
                    self.tcp_host or self.serial_port or 'auto-detect'
                )

                # Emit any already-known nodes from the node database
                self._emit_known_nodes()

                # Keep alive; packet callbacks arrive via pubsub
                while self._running and self._interface:
                    time.sleep(1)

            except Exception as e:
                logger.error("Meshtastic connection error: %s", e)
                if 'No Meshtastic' in str(e) or 'No device' in str(e) or 'serial' in str(e).lower():
                    logger.info("Retrying Meshtastic connection in 30 s")
                    time.sleep(30)
                else:
                    time.sleep(15)
            finally:
                if sub_handle:
                    try:
                        pub.unsubscribe(sub_handle, 'meshtastic.receive')
                    except Exception:
                        pass
                self._close_interface()

    def _emit_known_nodes(self):
        """Emit device callbacks for nodes already in the interface's node database."""
        try:
            if not self._interface or not hasattr(self._interface, 'nodes'):
                return
            nodes = self._interface.nodes or {}
            for node_id, node_info in nodes.items():
                user = node_info.get('user', {})
                position = node_info.get('position', {})
                long_name = user.get('longName') or user.get('shortName') or 'Unknown'
                device_id = f"MESH:{node_id}"
                self.device_callback(
                    device_id=device_id,
                    signal_type=self.SIGNAL_TYPE,
                    rssi=None,
                    metadata={
                        'node_name': long_name,
                        'portnum': 'NODEINFO_APP',
                        'snr': None,
                        'hop_limit': None,
                        'channel': 0,
                        'latitude': position.get('latitude'),
                        'longitude': position.get('longitude'),
                    }
                )
        except Exception as e:
            logger.debug("Could not emit known nodes: %s", e)
