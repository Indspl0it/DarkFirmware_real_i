#!/usr/bin/env python3
"""Real-time LMP packet monitor for DarkFirmware-patched RTL8761B.

Listens for HCI Vendor-Specific Events (0xFF) containing LMP RX logs
from the DarkFirmware LMP hook and decodes them in real-time.

Usage:
    sudo python3 lmp_monitor.py [--raw] [--json OUTPUT.json]

Options:
    --raw       Show raw hex bytes in addition to decoded output
    --json FILE Save captured LMP packets to BTIDES-format JSON file

Requires: DarkFirmware loaded on the dongle (run Patch Writer first).
          The dongle must NOT be claimed by the kernel (sudo hciconfig hciN down).
"""

import sys
import time
import json
import struct
import signal
import argparse

from darkfirmware_utils import recv_raw_bytes, MARKER_AAAA, MARKER_TXXX, MARKER_ACLX, MARKER_RXLC

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Hdr, HCI_Event_Command_Complete

# --- LMP Opcode Names ---
LMP_OPCODES = {
    0x01: "LMP_NAME_REQ",
    0x02: "LMP_NAME_RES",
    0x03: "LMP_ACCEPTED",
    0x04: "LMP_NOT_ACCEPTED",
    0x05: "LMP_CLKOFFSET_REQ",
    0x06: "LMP_CLKOFFSET_RES",
    0x07: "LMP_DETACH",
    0x08: "LMP_IN_RAND",
    0x09: "LMP_COMB_KEY",
    0x0A: "LMP_UNIT_KEY",
    0x0B: "LMP_AU_RAND",
    0x0C: "LMP_SRES",
    0x0D: "LMP_TEMP_RAND",
    0x0E: "LMP_TEMP_KEY",
    0x0F: "LMP_ENCRYPTION_MODE_REQ",
    0x10: "LMP_ENCRYPTION_KEY_SIZE_REQ",
    0x11: "LMP_START_ENCRYPTION_REQ",
    0x12: "LMP_STOP_ENCRYPTION_REQ",
    0x13: "LMP_SWITCH_REQ",
    0x14: "LMP_HOLD",
    0x15: "LMP_HOLD_REQ",
    0x17: "LMP_SNIFF_REQ",
    0x18: "LMP_UNSNIFF_REQ",
    0x1D: "LMP_SETUP_COMPLETE",
    0x1F: "LMP_MAX_SLOT",
    0x20: "LMP_MAX_SLOT_REQ",
    0x21: "LMP_TIMING_ACCURACY_REQ",
    0x22: "LMP_TIMING_ACCURACY_RES",
    0x25: "LMP_VERSION_REQ",
    0x26: "LMP_VERSION_RES",
    0x27: "LMP_FEATURES_REQ",
    0x28: "LMP_FEATURES_RES",
    0x2B: "LMP_QUALITY_OF_SERVICE",
    0x2C: "LMP_QUALITY_OF_SERVICE_REQ",
    0x31: "LMP_PAGE_MODE_REQ",
    0x32: "LMP_PAGE_SCAN_MODE_REQ",
    0x33: "LMP_SUPERVISION_TIMEOUT",
    0x34: "LMP_TEST_ACTIVATE",
    0x35: "LMP_TEST_CONTROL",
    0x36: "LMP_ENCRYPTION_KEY_SIZE_MASK_REQ",
    0x37: "LMP_ENCRYPTION_KEY_SIZE_MASK_RES",
    0x38: "LMP_SET_AFH",
    0x39: "LMP_ENCAPSULATED_HEADER",
    0x3A: "LMP_ENCAPSULATED_PAYLOAD",
    0x3B: "LMP_SIMPLE_PAIRING_CONFIRM",
    0x3C: "LMP_SIMPLE_PAIRING_NUMBER",
    0x3D: "LMP_DHKEY_CHECK",
    0x7F: "LMP_ESCAPE_4 (extended)",
}

LMP_EXT_OPCODES = {
    0x01: "EXT_ACCEPTED",
    0x02: "EXT_NOT_ACCEPTED",
    0x03: "EXT_FEATURES_REQ",
    0x04: "EXT_FEATURES_RES",
    0x05: "EXT_PACKET_TYPE_TABLE_REQ",
    0x06: "EXT_ESCO_LINK_REQ",
    0x07: "EXT_REMOVE_ESCO_LINK_REQ",
    0x0B: "EXT_IO_CAPABILITY_REQ",
    0x0C: "EXT_IO_CAPABILITY_RES",
    0x0D: "EXT_NUMERIC_COMPARISON_FAILED",
    0x0E: "EXT_PASSKEY_FAILED",
    0x0F: "EXT_OOB_FAILED",
    0x10: "EXT_KEYPRESS_NOTIFICATION",
    0x11: "EXT_POWER_CONTROL_REQ",
    0x12: "EXT_POWER_CONTROL_RES",
    0x17: "EXT_PING_REQ",
    0x18: "EXT_PING_RES",
}

# Log structure constants
MARKER_AAAA = 0x41414141  # RX (incoming LMP)
MARKER_BBBB = 0x42424242
MARKER_CCCC = 0x43434343
MARKER_TXXX = 0x58585854  # TX (outgoing LMP) — "TXXX" in LE
LMP_LOG_SIZE = 56
LMP_TX_LOG_SIZE = 12


def parse_lmp_tx_log(data: bytes) -> dict:
    """Parse a 12-byte LMP TX log from Hook 3 (tLC_TX).

    Format: [TX_MARKER:4B] [conn_idx:1B] [encoded_opcode:1B] [params:5B] [len:1B]
    """
    if len(data) < LMP_TX_LOG_SIZE:
        return None

    marker = struct.unpack_from("<I", data, 0x00)[0]
    if marker != MARKER_TXXX:
        return None

    conn_idx = data[4]
    encoded_opcode = data[5]
    opcode = encoded_opcode >> 1
    tid = encoded_opcode & 1
    params = data[6:11]
    length = data[11] + 1  # firmware stores length-1

    return {
        "direction": "TX",
        "conn_index": conn_idx,
        "lmp_opcode_raw_byte4": encoded_opcode,
        "lmp_opcode_decoded": opcode,
        "tid": tid,
        "params": params,
        "length": length,
        "raw": data,
    }


def parse_lmp_log(data: bytes) -> dict:
    """Parse an LMP log from HCI Event 0xFF. Handles both RX (56B) and TX (12B)."""
    if len(data) < LMP_TX_LOG_SIZE:
        return None

    # Check for TX marker first (smaller packet)
    marker = struct.unpack_from("<I", data, 0x00)[0]
    if marker == MARKER_TXXX:
        return parse_lmp_tx_log(data)

    # Check for RX marker (56-byte log)
    if len(data) < LMP_LOG_SIZE:
        return None
    if marker != MARKER_AAAA:
        return None  # Not our log event

    a0_ptr = struct.unpack_from("<I", data, 0x04)[0]
    data_buf_ptr = struct.unpack_from("<I", data, 0x08)[0]
    unknown_arg2 = struct.unpack_from("<I", data, 0x0C)[0]
    opcode_like = struct.unpack_from("<H", data, 0x10)[0]
    marker_b = struct.unpack_from("<I", data, 0x14)[0]

    result = {
        "direction": "RX",
        "a0_ptr": a0_ptr,
        "data_buf_ptr": data_buf_ptr,
        "unknown_arg2": unknown_arg2,
        "opcode_like": opcode_like,
        "has_data": True,
        "payload": data[0x18:0x34],
        "raw": data,
    }

    # Try to extract LMP opcode from payload
    # The data_buf_pointer layout: first 4 bytes often 0, LMP data starts at offset 4
    payload = data[0x18:0x34]
    if payload and len(payload) >= 5:
        # Try offset 4 (where LMP opcode typically lives)
        lmp_opcode_raw = payload[4]
        # LMP opcodes on-air are: (opcode << 1) | TID
        # But in the data buffer, it may be the raw opcode or encoded
        # Try both interpretations
        result["lmp_opcode_raw_byte4"] = lmp_opcode_raw
        result["lmp_opcode_decoded"] = lmp_opcode_raw >> 1  # Remove TID bit
        result["tid"] = lmp_opcode_raw & 1

    return result


def format_lmp_packet(log: dict, show_raw: bool = False) -> str:
    """Format a parsed LMP log for display."""
    lines = []
    ts = time.strftime("%H:%M:%S")

    opcode_raw = log.get("lmp_opcode_raw_byte4", 0)
    opcode_decoded = log.get("lmp_opcode_decoded", 0)
    tid = log.get("tid", 0)
    direction = log.get("direction", "??")

    # Try to identify the opcode
    name = LMP_OPCODES.get(opcode_decoded, f"UNKNOWN(0x{opcode_decoded:02x})")
    if opcode_decoded == 0x7F:
        params = log.get("params", log.get("payload", b""))
        if params and len(params) > 0:
            ext_op = params[0] if direction == "TX" else (log.get("payload", b"\x00" * 6)[5] if log.get("payload") else 0)
            ext_name = LMP_EXT_OPCODES.get(ext_op, f"UNKNOWN_EXT(0x{ext_op:02x})")
            name = f"LMP_ESCAPE_4/{ext_name}"

    # Color-coded direction
    dir_marker = f"{'<<' if direction == 'RX' else '>>'}"

    if direction == "TX":
        params_hex = log.get("params", b"").hex() if log.get("params") else ""
        conn = log.get("conn_index", 0)
        length = log.get("length", 0)
        lines.append(f"[{ts}] {dir_marker} TX {name} (opcode=0x{opcode_decoded:02x} TID={tid} conn={conn} len={length})")
        lines.append(f"       params: {params_hex}")
    else:
        payload_hex = log["payload"].hex() if log.get("payload") else ""
        lines.append(f"[{ts}] {dir_marker} RX {name} (raw=0x{opcode_raw:02x} decoded=0x{opcode_decoded:02x} TID={tid})")
        lines.append(f"       opcode_like=0x{log.get('opcode_like', 0):04x} a0=0x{log.get('a0_ptr', 0):08x} dbuf=0x{log.get('data_buf_ptr', 0):08x}")
        lines.append(f"       payload: {payload_hex}")

    if show_raw:
        lines.append(f"       raw: {log['raw'].hex()}")

    return "\n".join(lines)


class LMPMonitor:
    """Monitor LMP packets from DarkFirmware-patched RTL8761B."""

    def __init__(self):
        self.running = False
        self.packets = []
        self.socket = None

    def find_device(self):
        controllers = usbbluetooth.list_controllers()
        for c in controllers:
            if ((c.vendor_id == 0x0bda and c.product_id == 0xa728) or
                (c.vendor_id == 0x0bda and c.product_id == 0xa729) or
                (c.vendor_id == 0x2c0a and c.product_id == 0x8761) or
                (c.vendor_id == 0x2550 and c.product_id == 0x8761) or
                (c.vendor_id == 0x2357 and c.product_id == 0x0604)):
                return c
        return None

    def start(self, show_raw=False, json_file=None):
        """Start monitoring LMP packets."""
        ctrl = self.find_device()
        if ctrl is None:
            print("[!] No Realtek DarkFirmware device found")
            sys.exit(1)

        print(f"[+] Found device: VID=0x{ctrl.vendor_id:04x} PID=0x{ctrl.product_id:04x}")
        self.socket = UsbBluetoothSocket(ctrl)
        self.running = True

        print("[*] Monitoring LMP packets (Ctrl+C to stop)...")
        print("=" * 80)

        try:
            while self.running:
                try:
                    # Receive HCI event with timeout
                    raw = recv_raw_bytes(self.socket, timeout_ms=1000)
                    if raw is None:
                        continue

                    # raw is actual bytes from recv_raw_bytes()
                    if len(raw) < 3 or raw[0] != 0x04 or raw[1] != 0xFF:
                        continue

                    param_len = raw[2]
                    params = raw[3:3+param_len]

                    if len(params) < LMP_LOG_SIZE:
                        # Might be LMP TX echo (smaller), print raw
                        print(f"[*] HCI Event 0xFF ({len(params)}B): {params.hex()}")
                        continue

                    # Parse as LMP RX log
                    log = parse_lmp_log(params)
                    if log is None:
                        continue

                    self.packets.append(log)
                    print(format_lmp_packet(log, show_raw=show_raw))
                    print()

                except Exception as e:
                    if self.running:
                        print(f"[!] Receive error: {e}")
                    break

        except KeyboardInterrupt:
            pass

        print("=" * 80)
        print(f"[*] Captured {len(self.packets)} LMP packets")

        if json_file and self.packets:
            self._save_json(json_file)

    def stop(self):
        self.running = False

    def _save_json(self, filename):
        """Save captured packets in BTIDES-compatible format."""
        btides = []
        for pkt in self.packets:
            entry = {
                "opcode_like": pkt.get("opcode_like"),
                "lmp_opcode_decoded": pkt.get("lmp_opcode_decoded"),
                "tid": pkt.get("tid"),
                "payload_hex": pkt["payload"].hex() if pkt.get("payload") else "",
                "a0_ptr": f"0x{pkt.get('a0_ptr', 0):08x}",
                "data_buf_ptr": f"0x{pkt.get('data_buf_ptr', 0):08x}",
            }
            btides.append(entry)

        with open(filename, "w") as f:
            json.dump(btides, f, indent=2)
        print(f"[+] Saved {len(btides)} packets to {filename}")


def main():
    parser = argparse.ArgumentParser(description="DarkFirmware LMP Monitor")
    parser.add_argument("--raw", action="store_true", help="Show raw hex bytes")
    parser.add_argument("--json", metavar="FILE", help="Save to JSON file")
    args = parser.parse_args()

    monitor = LMPMonitor()

    def signal_handler(sig, frame):
        monitor.stop()

    signal.signal(signal.SIGINT, signal_handler)
    monitor.start(show_raw=args.raw, json_file=args.json)


if __name__ == "__main__":
    main()
