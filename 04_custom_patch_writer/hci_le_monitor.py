#!/usr/bin/env python3
"""HCI LE Command/Event Monitor for RTL8761B BLE research.

Monitors all HCI LE Controller commands (OGF 0x08) and LE Meta events
using a raw HCI socket. Shows BLE operations the controller handles.

Usage:
    sudo python3 hci_le_monitor.py [--hci hci1] [--all]

Options:
    --hci NAME  HCI interface to monitor (default: hci1)
    --all       Show ALL HCI commands/events, not just LE

This does NOT require DarkFirmware — works with any BT adapter.
BLE operations visible: scanning, advertising, connecting, encryption, etc.
"""

import sys
import struct
import socket
import argparse
import time
import signal

# HCI socket constants
HCI_DEV_NONE = 0xffff
HCI_CHANNEL_RAW = 0
HCI_CHANNEL_MONITOR = 2

# HCI packet types
HCI_COMMAND_PKT = 0x01
HCI_ACLDATA_PKT = 0x02
HCI_EVENT_PKT = 0x04

# OGF values
OGF_LE_CTL = 0x08

# LE OCF names
LE_OCF_NAMES = {
    0x0001: "LE_SET_EVENT_MASK",
    0x0002: "LE_READ_BUFFER_SIZE",
    0x0003: "LE_READ_LOCAL_SUPPORTED_FEATURES",
    0x0005: "LE_SET_RANDOM_ADDRESS",
    0x0006: "LE_SET_ADVERTISING_PARAMETERS",
    0x0008: "LE_SET_ADVERTISING_DATA",
    0x0009: "LE_SET_SCAN_RSP_DATA",
    0x000A: "LE_SET_ADVERTISE_ENABLE",
    0x000B: "LE_SET_SCAN_PARAMETERS",
    0x000C: "LE_SET_SCAN_ENABLE",
    0x000D: "LE_CREATE_CONNECTION",
    0x000E: "LE_CREATE_CONNECTION_CANCEL",
    0x000F: "LE_READ_FILTER_ACCEPT_LIST_SIZE",
    0x0010: "LE_CLEAR_FILTER_ACCEPT_LIST",
    0x0011: "LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST",
    0x0012: "LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST",
    0x0013: "LE_CONNECTION_UPDATE",
    0x0014: "LE_SET_HOST_CHANNEL_CLASSIFICATION",
    0x0015: "LE_READ_CHANNEL_MAP",
    0x0017: "LE_ENCRYPT",
    0x0018: "LE_RAND",
    0x0019: "LE_ENABLE_ENCRYPTION",
    0x001A: "LE_LONG_TERM_KEY_REQUEST_REPLY",
    0x001B: "LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY",
    0x001C: "LE_READ_SUPPORTED_STATES",
    0x001D: "LE_RECEIVER_TEST",
    0x001E: "LE_TRANSMITTER_TEST",
    0x001F: "LE_TEST_END",
    0x0020: "LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY",
    0x0024: "LE_SET_DATA_LENGTH",
    0x0025: "LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH",
    0x0027: "LE_ADD_DEVICE_TO_RESOLVING_LIST",
    0x0029: "LE_CLEAR_RESOLVING_LIST",
    0x002B: "LE_SET_ADDRESS_RESOLUTION_ENABLE",
    0x002F: "LE_READ_PHY",
    0x0030: "LE_SET_DEFAULT_PHY",
    0x0031: "LE_SET_PHY",
    0x0036: "LE_SET_EXTENDED_ADVERTISING_PARAMETERS",
    0x0037: "LE_SET_EXTENDED_ADVERTISING_DATA",
    0x0039: "LE_SET_EXTENDED_ADVERTISING_ENABLE",
    0x0041: "LE_SET_EXTENDED_SCAN_PARAMETERS",
    0x0042: "LE_SET_EXTENDED_SCAN_ENABLE",
    0x0043: "LE_EXTENDED_CREATE_CONNECTION",
}

# HCI Event codes
HCI_EVENT_NAMES = {
    0x05: "DISCONNECTION_COMPLETE",
    0x08: "ENCRYPTION_CHANGE",
    0x0E: "COMMAND_COMPLETE",
    0x0F: "COMMAND_STATUS",
    0x13: "NUMBER_OF_COMPLETED_PACKETS",
    0x30: "ENCRYPTION_KEY_REFRESH_COMPLETE",
    0x3E: "LE_META_EVENT",
    0xFF: "VENDOR_SPECIFIC",
}

# LE Meta subevent codes
LE_META_NAMES = {
    0x01: "LE_CONNECTION_COMPLETE",
    0x02: "LE_ADVERTISING_REPORT",
    0x03: "LE_CONNECTION_UPDATE_COMPLETE",
    0x04: "LE_READ_REMOTE_FEATURES_COMPLETE",
    0x05: "LE_LONG_TERM_KEY_REQUEST",
    0x07: "LE_DATA_LENGTH_CHANGE",
    0x08: "LE_READ_LOCAL_P256_PUBLIC_KEY_COMPLETE",
    0x09: "LE_GENERATE_DHKEY_COMPLETE",
    0x0A: "LE_ENHANCED_CONNECTION_COMPLETE",
    0x0B: "LE_DIRECTED_ADVERTISING_REPORT",
    0x0C: "LE_PHY_UPDATE_COMPLETE",
    0x0D: "LE_EXTENDED_ADVERTISING_REPORT",
    0x0E: "LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED",
    0x12: "LE_CHANNEL_SELECTION_ALGORITHM",
}


def open_hci_monitor(hci_dev="hci1"):
    """Open a raw HCI socket for monitoring."""
    dev_id = int(hci_dev.replace("hci", ""))

    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    # Set filter to accept all HCI packet types
    flt = struct.pack('<IIIhh', 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0)
    sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, flt)
    sock.bind((dev_id,))
    sock.settimeout(1.0)
    return sock


def decode_command(data):
    """Decode an HCI command packet."""
    if len(data) < 3:
        return None
    opcode = struct.unpack_from("<H", data, 0)[0]
    plen = data[2]
    ogf = (opcode >> 10) & 0x3F
    ocf = opcode & 0x03FF
    params = data[3:3+plen]
    return {"ogf": ogf, "ocf": ocf, "opcode": opcode, "params": params}


def decode_event(data):
    """Decode an HCI event packet."""
    if len(data) < 2:
        return None
    event_code = data[0]
    plen = data[1]
    params = data[2:2+plen]
    return {"event_code": event_code, "params": params}


def format_command(cmd, show_all=False):
    """Format a decoded HCI command for display."""
    ogf = cmd["ogf"]
    ocf = cmd["ocf"]

    if ogf == OGF_LE_CTL:
        name = LE_OCF_NAMES.get(ocf, f"LE_UNKNOWN(0x{ocf:04x})")
        return f"[CMD] {name} (OGF=0x{ogf:02x} OCF=0x{ocf:04x}) params={cmd['params'].hex()}"
    elif ogf == 0x3F:  # Vendor-specific
        if show_all:
            return f"[CMD] VENDOR_SPECIFIC (OCF=0x{ocf:04x}) params={cmd['params'][:16].hex()}..."
    elif show_all:
        return f"[CMD] OGF=0x{ogf:02x} OCF=0x{ocf:04x} params={cmd['params'][:16].hex()}"
    return None


def format_event(evt, show_all=False):
    """Format a decoded HCI event for display."""
    code = evt["event_code"]
    params = evt["params"]

    if code == 0x3E:  # LE Meta Event
        if len(params) >= 1:
            subevent = params[0]
            name = LE_META_NAMES.get(subevent, f"LE_UNKNOWN_META(0x{subevent:02x})")
            return f"[EVT] {name} (subevent=0x{subevent:02x}) params={params[1:17].hex()}"
    elif code == 0x08:  # Encryption Change
        if len(params) >= 4:
            status = params[0]
            handle = struct.unpack_from("<H", params, 1)[0]
            enabled = params[3]
            return f"[EVT] ENCRYPTION_CHANGE handle=0x{handle:04x} enabled={enabled} status={status}"
    elif code == 0xFF and show_all:
        return f"[EVT] VENDOR_SPECIFIC ({len(params)}B)"
    elif show_all:
        name = HCI_EVENT_NAMES.get(code, f"UNKNOWN(0x{code:02x})")
        return f"[EVT] {name} params={params[:16].hex()}"
    return None


def main():
    parser = argparse.ArgumentParser(description="HCI LE Command/Event Monitor")
    parser.add_argument("--hci", default="hci1", help="HCI interface")
    parser.add_argument("--all", action="store_true", help="Show all HCI, not just LE")
    args = parser.parse_args()

    print(f"[+] Monitoring {args.hci} for BLE traffic (Ctrl+C to stop)...")
    print("=" * 80)

    try:
        sock = open_hci_monitor(args.hci)
    except Exception as e:
        print(f"[!] Failed to open HCI socket: {e}")
        print(f"    Make sure {args.hci} is UP: sudo hciconfig {args.hci} up")
        sys.exit(1)

    running = True
    def handler(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, handler)

    cmd_count = 0
    evt_count = 0

    try:
        while running:
            try:
                data = sock.recv(1024)
                if not data:
                    continue

                ts = time.strftime("%H:%M:%S")
                pkt_type = data[0]

                if pkt_type == HCI_COMMAND_PKT:
                    cmd = decode_command(data[1:])
                    if cmd:
                        line = format_command(cmd, show_all=args.all)
                        if line:
                            cmd_count += 1
                            print(f"[{ts}] {line}")

                elif pkt_type == HCI_EVENT_PKT:
                    evt = decode_event(data[1:])
                    if evt:
                        line = format_event(evt, show_all=args.all)
                        if line:
                            evt_count += 1
                            print(f"[{ts}] {line}")

            except socket.timeout:
                continue
            except OSError:
                break

    except KeyboardInterrupt:
        pass

    print("=" * 80)
    print(f"[*] Captured {cmd_count} LE commands, {evt_count} LE events")


if __name__ == "__main__":
    main()
