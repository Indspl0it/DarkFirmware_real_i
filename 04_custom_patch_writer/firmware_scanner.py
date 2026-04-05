#!/usr/bin/env python3
"""RTL8761B Firmware Memory Scanner for RE research.

Scans controller ROM/RAM via VSC 0xFC61 for:
- ASCII strings (find BLE handler registrations, debug strings)
- Address references (find callers of specific functions)
- Byte patterns (find specific instruction sequences)

Usage:
    sudo python3 firmware_scanner.py strings [--region ROM|RAM|ALL] [--min-len N]
    sudo python3 firmware_scanner.py refs ADDRESS [--region ROM|RAM]
    sudo python3 firmware_scanner.py dump START END [--output FILE]
    sudo python3 firmware_scanner.py pattern HEXBYTES [--region ROM|RAM]

Examples:
    sudo python3 firmware_scanner.py strings --min-len 4          # Find all 4+ char strings
    sudo python3 firmware_scanner.py strings --filter "tL,tH,BLE,LE_,ll_"  # Search specific
    sudo python3 firmware_scanner.py refs 0x800611E5              # Find send_LMP_reply callers
    sudo python3 firmware_scanner.py dump 0x80000000 0x80001000   # Dump memory region
    sudo python3 firmware_scanner.py pattern E5110680              # Find address in memory

Requires: DarkFirmware loaded. Run Patch Writer first, use in same session.
"""

import sys
import struct
import argparse
import time

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

# Memory regions
ROM_START = 0x80000000
ROM_END   = 0x80100000  # 1MB ROM
RAM_START = 0x80100000
RAM_END   = 0x80134000  # ~200KB RAM

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
    """Read 4 bytes from controller memory. Returns bytes or None."""
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=addr)
    try:
        resp = sock.sr1(pkt, verbose=0, timeout=2)
        if HCI_Event_Command_Complete in resp and resp[HCI_Event_Command_Complete].status == 0:
            data = resp.data
            if isinstance(data, (bytes, bytearray)):
                return bytes(data[:4])
            return data.to_bytes(4, 'little')
    except Exception:
        pass
    return None


def read_region(sock, start, end, progress=True):
    """Read a memory region in 4-byte chunks. Returns bytearray."""
    data = bytearray()
    total = end - start
    read_count = 0

    for addr in range(start, end, 4):
        chunk = read4(sock, addr)
        if chunk is None:
            data.extend(b'\xDE\xAD\xBE\xEF')
        else:
            data.extend(chunk)

        read_count += 4
        if progress and read_count % 4096 == 0:
            pct = (read_count / total) * 100
            print(f"\r  [{pct:5.1f}%] 0x{addr:08X} ({read_count}/{total} bytes)", end="", flush=True)

    if progress:
        print()
    return data


def scan_strings(sock, start, end, min_len=4, filter_terms=None):
    """Scan memory for ASCII strings."""
    print(f"[*] Scanning for strings in 0x{start:08X}-0x{end:08X} (min_len={min_len})...")

    data = read_region(sock, start, end)
    strings_found = []
    current_str = ""
    str_start = 0

    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current_str:
                str_start = i
            current_str += chr(b)
        else:
            if len(current_str) >= min_len:
                addr = start + str_start
                if filter_terms is None or any(t.lower() in current_str.lower() for t in filter_terms):
                    strings_found.append((addr, current_str))
            current_str = ""

    # Print results
    print(f"\n[*] Found {len(strings_found)} strings:")
    for addr, s in strings_found:
        print(f"  0x{addr:08X}: \"{s}\"")

    return strings_found


def scan_refs(sock, target_addr, start, end):
    """Scan memory for 4-byte references to a target address."""
    target_bytes = struct.pack("<I", target_addr)
    print(f"[*] Scanning for references to 0x{target_addr:08X} in 0x{start:08X}-0x{end:08X}...")

    data = read_region(sock, start, end)
    refs = []

    for i in range(0, len(data) - 3, 4):  # 4-byte aligned
        if data[i:i+4] == target_bytes:
            addr = start + i
            refs.append(addr)

    # Also search unaligned (2-byte aligned for MIPS16e)
    for i in range(0, len(data) - 3, 2):
        if data[i:i+4] == target_bytes:
            addr = start + i
            if addr not in refs:
                refs.append(addr)

    print(f"\n[*] Found {len(refs)} reference(s) to 0x{target_addr:08X}:")
    for addr in sorted(refs):
        # Show context (8 bytes before and after)
        offset = addr - start
        ctx_start = max(0, offset - 8)
        ctx_end = min(len(data), offset + 12)
        ctx = data[ctx_start:ctx_end].hex()
        print(f"  0x{addr:08X}: ...{ctx}...")

    return refs


def scan_pattern(sock, pattern_hex, start, end):
    """Scan memory for a byte pattern."""
    pattern = bytes.fromhex(pattern_hex)
    print(f"[*] Scanning for pattern {pattern_hex} in 0x{start:08X}-0x{end:08X}...")

    data = read_region(sock, start, end)
    matches = []

    pos = 0
    while True:
        idx = data.find(pattern, pos)
        if idx == -1:
            break
        addr = start + idx
        matches.append(addr)
        pos = idx + 1

    print(f"\n[*] Found {len(matches)} match(es):")
    for addr in matches:
        offset = addr - start
        ctx_start = max(0, offset - 4)
        ctx_end = min(len(data), offset + len(pattern) + 4)
        ctx = data[ctx_start:ctx_end].hex()
        print(f"  0x{addr:08X}: ...{ctx}...")

    return matches


def dump_memory(sock, start, end, output_file=None):
    """Dump a memory region."""
    print(f"[*] Dumping 0x{start:08X}-0x{end:08X} ({end-start} bytes)...")
    data = read_region(sock, start, end)

    if output_file:
        with open(output_file, "wb") as f:
            f.write(data)
        print(f"[+] Saved {len(data)} bytes to {output_file}")
    else:
        # Hex dump
        for i in range(0, len(data), 16):
            addr = start + i
            hex_bytes = ' '.join(f'{b:02x}' for b in data[i:i+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
            print(f"  0x{addr:08X}: {hex_bytes:<48s} |{ascii_str}|")

    return data


def get_region(region_name):
    """Get start/end addresses for a named region."""
    regions = {
        "rom": (ROM_START, ROM_END),
        "ram": (RAM_START, RAM_END),
        "all": (ROM_START, RAM_END),
        "patch": (0x80100000, 0x80120000),
        "hooks": (0x80133F00, 0x80134000),
        "conn": (0x8012DC50, 0x8012DC50 + 12 * 500),
    }
    return regions.get(region_name.lower(), (ROM_START, ROM_END))


def main():
    parser = argparse.ArgumentParser(description="RTL8761B Firmware Memory Scanner")
    sub = parser.add_subparsers(dest="command")

    # strings command
    p_str = sub.add_parser("strings", help="Scan for ASCII strings")
    p_str.add_argument("--region", default="rom", help="Region: rom, ram, all, patch")
    p_str.add_argument("--min-len", type=int, default=4, help="Minimum string length")
    p_str.add_argument("--filter", help="Comma-separated filter terms")

    # refs command
    p_ref = sub.add_parser("refs", help="Find references to an address")
    p_ref.add_argument("address", type=lambda x: int(x, 0), help="Target address (hex)")
    p_ref.add_argument("--region", default="rom", help="Region to scan")

    # dump command
    p_dump = sub.add_parser("dump", help="Dump memory region")
    p_dump.add_argument("start", type=lambda x: int(x, 0), help="Start address")
    p_dump.add_argument("end", type=lambda x: int(x, 0), help="End address")
    p_dump.add_argument("--output", help="Output binary file")

    # pattern command
    p_pat = sub.add_parser("pattern", help="Search for byte pattern")
    p_pat.add_argument("hexbytes", help="Pattern in hex (e.g., E5110680)")
    p_pat.add_argument("--region", default="rom", help="Region to scan")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    ctrl = find_realtek_device()
    if ctrl is None:
        print("[!] No Realtek device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)
    print(f"[+] Connected to device")

    if args.command == "strings":
        start, end = get_region(args.region)
        filters = args.filter.split(",") if args.filter else None
        scan_strings(sock, start, end, args.min_len, filters)

    elif args.command == "refs":
        start, end = get_region(args.region)
        scan_refs(sock, args.address, start, end)

    elif args.command == "dump":
        dump_memory(sock, args.start, args.end, args.output)

    elif args.command == "pattern":
        start, end = get_region(args.region)
        scan_pattern(sock, args.hexbytes, start, end)


if __name__ == "__main__":
    main()
