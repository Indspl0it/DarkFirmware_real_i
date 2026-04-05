#!/usr/bin/env python3
"""BLE Connection Table Mapper for RTL8761B.

Maps BLE-specific fields in the connection table by diffing dumps
before and after BLE connections. Also identifies link key locations.

Usage:
    sudo python3 ble_conn_mapper.py baseline              # Dump baseline (no connection)
    sudo python3 ble_conn_mapper.py snapshot NAME          # Dump after connecting, save as NAME
    sudo python3 ble_conn_mapper.py diff BASELINE SNAPSHOT # Compare two dumps
    sudo python3 ble_conn_mapper.py watch [--interval N]   # Continuous monitoring

Workflow:
    1. Flash DarkFirmware, bring up dongle
    2. sudo python3 ble_conn_mapper.py baseline
    3. bluetoothctl connect <BLE_DEVICE>
    4. sudo python3 ble_conn_mapper.py snapshot after_ble_connect
    5. sudo python3 ble_conn_mapper.py diff baseline.slot0.bin after_ble_connect.slot0.bin
"""

import sys
import os
import struct
import time
import argparse

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

CONN_TABLE_BASE = 0x8012DC50
SLOT_SIZE = 0x2B8  # 696 bytes (confirmed via RE)
MAX_SLOTS = 12
DUMP_DIR = "conn_dumps"

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000)]
class HCI_Cmd_Complete_VSC(Packet):
    name = 'VSC complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc61)


def find_realtek_device():
    controllers = usbbluetooth.list_controllers()
    for c in controllers:
        if ((c.vendor_id == 0x0bda and c.product_id == 0xa728) or
            (c.vendor_id == 0x0bda and c.product_id == 0xa729) or
            (c.vendor_id == 0x2c0a and c.product_id == 0x8761) or
            (c.vendor_id == 0x2550 and c.product_id == 0x8761) or
            (c.vendor_id == 0x2357 and c.product_id == 0x0604)):
            return c
    return None


def read4(sock, addr):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=addr)
    try:
        resp = sock.sr1(pkt, verbose=0, timeout=2)
        if HCI_Event_Command_Complete in resp and resp[HCI_Event_Command_Complete].status == 0:
            data = resp.data
            return bytes(data[:4]) if isinstance(data, (bytes, bytearray)) else data.to_bytes(4, 'little')
    except Exception:
        pass
    return None


def dump_slot(sock, slot_idx):
    base = CONN_TABLE_BASE + (slot_idx * SLOT_SIZE)
    data = bytearray()
    for offset in range(0, SLOT_SIZE, 4):
        chunk = read4(sock, base + offset)
        data.extend(chunk if chunk else b'\xDE\xAD\xBE\xEF')
    return bytes(data[:SLOT_SIZE])


def analyze_slot(data, slot_idx):
    """Analyze a connection slot for interesting fields."""
    base = CONN_TABLE_BASE + (slot_idx * SLOT_SIZE)
    findings = []

    # Check if slot is active
    bdaddr = data[:6]
    if all(b == 0 for b in bdaddr) or all(b == 0xFF for b in bdaddr):
        findings.append(("EMPTY", 0, "Slot is not active"))
        return findings

    bdaddr_str = ':'.join(f'{b:02X}' for b in reversed(bdaddr))
    findings.append(("BD_ADDR", 0, f"BD Address: {bdaddr_str}"))

    # Look for patterns that suggest encryption state, link keys, etc.
    # 16-byte non-zero sequences could be link keys
    for offset in range(0, SLOT_SIZE - 15, 4):
        block = data[offset:offset+16]
        non_zero = sum(1 for b in block if b != 0 and b != 0xFF)
        if non_zero >= 12:  # At least 12 of 16 bytes are meaningful
            # Check if it looks random (link key candidate)
            unique = len(set(block))
            if unique >= 8:  # High entropy
                findings.append(("KEY_CANDIDATE", offset,
                    f"16-byte high-entropy block: {block.hex()}"))

    # Look for small non-zero values that might be state flags
    for offset in range(6, min(64, SLOT_SIZE)):
        b = data[offset]
        if 1 <= b <= 16:  # Could be key size, connection state, etc.
            findings.append(("STATE_BYTE", offset, f"Value: {b} (0x{b:02x})"))

    return findings


def diff_slots(data_a, data_b, base_addr):
    """Detailed diff of two slot dumps."""
    changes = []
    for i in range(min(len(data_a), len(data_b))):
        if data_a[i] != data_b[i]:
            changes.append((i, data_a[i], data_b[i]))

    if not changes:
        print("[*] No differences found")
        return []

    print(f"[*] {len(changes)} byte(s) changed:")

    # Group into contiguous regions
    regions = []
    start = changes[0][0]
    end = start
    for off, _, _ in changes[1:]:
        if off <= end + 2:  # Allow 2-byte gap
            end = off
        else:
            regions.append((start, end))
            start = off
            end = off
    regions.append((start, end))

    for rstart, rend in regions:
        rlen = rend - rstart + 1
        addr = base_addr + rstart
        old_bytes = data_a[rstart:rend+1]
        new_bytes = data_b[rstart:rend+1]

        label = ""
        if rlen == 6 and rstart < 8:
            label = " [BD_ADDR]"
        elif rlen >= 16:
            label = " [POSSIBLE LINK KEY]"
        elif rlen == 1 and 1 <= new_bytes[0] <= 16:
            label = f" [KEY_SIZE={new_bytes[0]}?]"
        elif rlen == 2:
            label = " [CONNECTION_HANDLE?]"

        print(f"  +0x{rstart:04X} (0x{addr:08X}): {rlen}B changed{label}")
        print(f"    Before: {old_bytes.hex()}")
        print(f"    After:  {new_bytes.hex()}")

    return regions


def main():
    parser = argparse.ArgumentParser(description="BLE Connection Table Mapper")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("baseline", help="Dump baseline (no connection)")
    p_snap = sub.add_parser("snapshot", help="Dump snapshot after connection")
    p_snap.add_argument("name", help="Snapshot name")
    p_snap.add_argument("--slot", type=int, default=0)

    p_diff = sub.add_parser("diff", help="Compare two dumps")
    p_diff.add_argument("file_a", help="Before dump")
    p_diff.add_argument("file_b", help="After dump")

    p_watch = sub.add_parser("watch", help="Continuous monitoring")
    p_watch.add_argument("--interval", type=int, default=5, help="Seconds between dumps")
    p_watch.add_argument("--slot", type=int, default=0)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "diff":
        with open(args.file_a, "rb") as f:
            data_a = f.read()
        with open(args.file_b, "rb") as f:
            data_b = f.read()
        print(f"[*] Diffing {args.file_a} vs {args.file_b}")
        diff_slots(data_a, data_b, CONN_TABLE_BASE)
        return

    # Commands that need USB connection
    ctrl = find_realtek_device()
    if ctrl is None:
        print("[!] No Realtek device found")
        sys.exit(1)
    sock = UsbBluetoothSocket(ctrl)

    os.makedirs(DUMP_DIR, exist_ok=True)

    if args.command == "baseline":
        print("[*] Dumping baseline (all slots)...")
        for slot in range(MAX_SLOTS):
            base = CONN_TABLE_BASE + (slot * SLOT_SIZE)
            data = dump_slot(sock, slot)
            fname = f"{DUMP_DIR}/baseline.slot{slot}.bin"
            with open(fname, "wb") as f:
                f.write(data)

            findings = analyze_slot(data, slot)
            status = findings[0][2] if findings else "?"
            if findings[0][0] != "EMPTY":
                print(f"  Slot {slot}: ACTIVE — {status}")
                for kind, offset, desc in findings[1:]:
                    print(f"    +0x{offset:04X}: [{kind}] {desc}")
            else:
                print(f"  Slot {slot}: empty")
        print(f"[+] Saved to {DUMP_DIR}/baseline.slot*.bin")

    elif args.command == "snapshot":
        slot = args.slot
        print(f"[*] Dumping slot {slot} as '{args.name}'...")
        data = dump_slot(sock, slot)
        fname = f"{DUMP_DIR}/{args.name}.slot{slot}.bin"
        with open(fname, "wb") as f:
            f.write(data)
        findings = analyze_slot(data, slot)
        for kind, offset, desc in findings:
            print(f"  +0x{offset:04X}: [{kind}] {desc}")
        print(f"[+] Saved to {fname}")

        # Auto-diff against baseline if it exists
        baseline = f"{DUMP_DIR}/baseline.slot{slot}.bin"
        if os.path.exists(baseline):
            print(f"\n[*] Auto-diff against baseline:")
            with open(baseline, "rb") as f:
                base_data = f.read()
            diff_slots(base_data, data, CONN_TABLE_BASE + slot * SLOT_SIZE)

    elif args.command == "watch":
        slot = args.slot
        print(f"[*] Watching slot {slot} every {args.interval}s (Ctrl+C to stop)...")
        prev_data = dump_slot(sock, slot)
        print(f"  Initial dump taken")

        try:
            while True:
                time.sleep(args.interval)
                curr_data = dump_slot(sock, slot)
                if curr_data != prev_data:
                    ts = time.strftime("%H:%M:%S")
                    print(f"\n[{ts}] Change detected in slot {slot}:")
                    diff_slots(prev_data, curr_data, CONN_TABLE_BASE + slot * SLOT_SIZE)
                    prev_data = curr_data
                else:
                    print(".", end="", flush=True)
        except KeyboardInterrupt:
            print("\n[*] Stopped")


if __name__ == "__main__":
    main()
