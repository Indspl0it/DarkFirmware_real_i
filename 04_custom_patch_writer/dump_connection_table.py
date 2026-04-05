#!/usr/bin/env python3
"""Dump RTL8761B connection table for link key extraction research.

Reads the big_ol_struct connection table at 0x8012DC50 via VSC 0xFC61.
Each of the 12 connection slots is ~500 bytes containing BD_ADDR,
encryption state, link keys, and other per-connection state.

Usage:
    sudo python3 dump_connection_table.py [--slot N] [--output FILE] [--all]

Options:
    --slot N     Dump specific slot (0-11, default: 0)
    --all        Dump all 12 slots
    --output FILE  Save raw binary to file (default: stdout hex dump)
    --diff FILE    Diff current dump against a previous binary dump

Requires: DarkFirmware loaded. Run Patch Writer first, then use this
          in the SAME session (no HCI reset between).
"""

import sys
import struct
import argparse

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

CONN_TABLE_BASE = 0x8012DC50
SLOT_SIZE = 0x2B8  # 696 bytes (confirmed via RE)
MAX_SLOTS = 12

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000)]

class HCI_Cmd_Complete_VSC_Realtek_Read_Mem(Packet):
    name = 'Read complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Read_Mem, opcode=0xfc61)


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


def read_mem(sock, addr):
    """Read 4 bytes from controller memory."""
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=addr)
    resp = sock.sr1(pkt, verbose=0)
    if HCI_Event_Command_Complete in resp and resp[HCI_Event_Command_Complete].status == 0:
        return resp.data
    return None


def dump_slot(sock, slot_idx, size=SLOT_SIZE):
    """Read a full connection slot from controller memory."""
    base = CONN_TABLE_BASE + (slot_idx * size)
    data = bytearray()

    for offset in range(0, size, 4):
        addr = base + offset
        chunk = read_mem(sock, addr)
        if chunk is None:
            print(f"[!] Read failed at 0x{addr:08X}")
            data.extend(b'\xDE\xAD\xBE\xEF')
        elif isinstance(chunk, (bytes, bytearray)):
            data.extend(chunk[:4])
        else:
            data.extend(chunk.to_bytes(4, 'little'))

    return bytes(data[:size])


def hex_dump(data, base_addr=0, highlight_ranges=None):
    """Print hex dump with ASCII sidebar."""
    lines = []
    for i in range(0, len(data), 16):
        addr = base_addr + i
        hex_bytes = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])

        # Highlight non-zero regions
        has_data = any(b != 0 and b != 0xFF and b != 0xCC for b in data[i:i+16])
        marker = "***" if has_data else "   "

        lines.append(f"  0x{addr:08X}: {hex_bytes:<48s} |{ascii_str}| {marker}")
    return '\n'.join(lines)


def diff_dumps(current, previous, base_addr=0):
    """Show differences between two dumps."""
    changes = []
    for i in range(min(len(current), len(previous))):
        if current[i] != previous[i]:
            changes.append((i, previous[i], current[i]))

    if not changes:
        print("[*] No differences found")
        return

    print(f"[*] {len(changes)} byte(s) changed:")
    for offset, old, new in changes:
        addr = base_addr + offset
        print(f"  0x{addr:08X} (+0x{offset:04X}): 0x{old:02X} -> 0x{new:02X}")

    # Look for 16-byte sequences that changed (possible link key)
    if len(changes) >= 16:
        # Find contiguous changed regions
        regions = []
        start = changes[0][0]
        end = start
        for off, _, _ in changes[1:]:
            if off == end + 1:
                end = off
            else:
                regions.append((start, end))
                start = off
                end = off
        regions.append((start, end))

        for rstart, rend in regions:
            rlen = rend - rstart + 1
            if rlen >= 16:
                print(f"\n  [!] {rlen}-byte region changed at offset +0x{rstart:04X} (possible link key!)")
                print(f"      Old: {previous[rstart:rend+1].hex()}")
                print(f"      New: {current[rstart:rend+1].hex()}")


def main():
    parser = argparse.ArgumentParser(description="DarkFirmware Connection Table Dumper")
    parser.add_argument("--slot", type=int, default=0, help="Slot index (0-11)")
    parser.add_argument("--all", action="store_true", help="Dump all 12 slots")
    parser.add_argument("--output", metavar="FILE", help="Save raw binary to file")
    parser.add_argument("--diff", metavar="FILE", help="Diff against previous dump")
    parser.add_argument("--size", type=int, default=SLOT_SIZE, help="Slot size in bytes")
    args = parser.parse_args()

    ctrl = find_realtek_device()
    if ctrl is None:
        print("[!] No Realtek device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)
    print(f"[+] Connected to VID=0x{ctrl.vendor_id:04x} PID=0x{ctrl.product_id:04x}")

    slots = range(MAX_SLOTS) if args.all else [args.slot]

    for slot_idx in slots:
        if slot_idx < 0 or slot_idx >= MAX_SLOTS:
            print(f"[!] Invalid slot {slot_idx} (must be 0-{MAX_SLOTS-1})")
            continue

        base = CONN_TABLE_BASE + (slot_idx * args.size)
        print(f"\n[*] Dumping slot {slot_idx} at 0x{base:08X} ({args.size} bytes)...")

        data = dump_slot(sock, slot_idx, args.size)

        # Check if slot appears active (first 6 bytes = BD_ADDR)
        bdaddr = data[:6]
        if all(b == 0 for b in bdaddr):
            print(f"[*] Slot {slot_idx}: EMPTY (BD_ADDR all zeros)")
        elif all(b == 0xFF for b in bdaddr):
            print(f"[*] Slot {slot_idx}: EMPTY (BD_ADDR all 0xFF)")
        else:
            # RTL stores BD_ADDR in little-endian
            bdaddr_str = ':'.join(f'{b:02X}' for b in reversed(bdaddr))
            print(f"[+] Slot {slot_idx}: ACTIVE — BD_ADDR = {bdaddr_str}")

        print(hex_dump(data, base))

        if args.output:
            outfile = f"{args.output}.slot{slot_idx}" if args.all else args.output
            with open(outfile, "wb") as f:
                f.write(data)
            print(f"[+] Saved to {outfile}")

        if args.diff:
            difffile = f"{args.diff}.slot{slot_idx}" if args.all else args.diff
            try:
                with open(difffile, "rb") as f:
                    prev = f.read()
                print(f"\n[*] Diffing against {difffile}:")
                diff_dumps(data, prev, base)
            except FileNotFoundError:
                print(f"[!] Diff file not found: {difffile}")


if __name__ == "__main__":
    main()
