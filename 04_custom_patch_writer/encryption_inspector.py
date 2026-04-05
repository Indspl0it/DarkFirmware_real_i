#!/usr/bin/env python3
"""RTL8761B Encryption State Inspector — reads connection security state from controller RAM.

Extracts encryption key size, encryption enabled flag, link key material,
Secure Connections status, and auth state from the live connection table.

Usage:
    sudo python3 encryption_inspector.py [--conn N] [--watch]

Requires: DarkFirmware loaded, active connection on specified slot.
          Must be in same USB session as Patch Writer (no HCI reset).

What it reads:
    - Negotiated encryption key size (offset 0x23 in secondary struct)
    - Encryption enabled flag (offset 0x26)
    - Link key material candidates (offsets 0x02 and 0x51, 16 bytes each)
    - Secure Connections flag (offset 0x214)
    - Auth state machine (offset 0x50)
"""

import sys
import struct
import time
import argparse

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

BOS_BASE = 0x8012DC50
SLOT_SIZE_ESTIMATE = 0x2B8  # 696 bytes (confirmed via RE)
SECONDARY_PTR_OFFSET = 0x58

# Offsets within secondary struct (pointed to by bos[n]+0x58)
OFF_STATE_BYTE = 0x01
OFF_KEY_MATERIAL_SRC = 0x02   # 16 bytes
OFF_PAIRING_STAGE = 0x12
OFF_KEY_SIZE = 0x23           # Negotiated encryption key size (1-16)
OFF_ENC_ENABLED = 0x26        # Encryption enabled boolean
OFF_AUTH_STATE = 0x50
OFF_KEY_MATERIAL_COPY = 0x51  # 16 bytes — key copy during COMB_KEY
OFF_SC_FLAG = 0x214           # Secure Connections enabled

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


def read_bytes(sock, addr, count):
    """Read N bytes from controller memory (4-byte aligned reads)."""
    data = bytearray()
    for off in range(0, count, 4):
        chunk = read4(sock, addr + off)
        if chunk:
            data.extend(chunk)
        else:
            data.extend(b'\x00\x00\x00\x00')
    return bytes(data[:count])


def read_byte(sock, addr):
    """Read single byte."""
    data = read4(sock, addr & ~3)  # Align to 4-byte boundary
    if data:
        byte_offset = addr & 3
        return data[byte_offset]
    return None


def inspect_connection(sock, conn_index):
    """Read encryption state for a connection slot."""
    bos_addr = BOS_BASE + (conn_index * SLOT_SIZE_ESTIMATE)

    # Read BD address (first 6 bytes of slot)
    bdaddr_data = read_bytes(sock, bos_addr, 8)
    bdaddr = bdaddr_data[:6]

    if all(b == 0 for b in bdaddr) or all(b == 0xFF for b in bdaddr):
        return {"active": False, "conn_index": conn_index}

    bdaddr_str = ':'.join(f'{b:02X}' for b in reversed(bdaddr))

    # Read pointer to secondary struct at offset 0x58
    ptr_data = read4(sock, bos_addr + SECONDARY_PTR_OFFSET)
    if not ptr_data:
        return {"active": True, "bdaddr": bdaddr_str, "error": "Failed to read secondary ptr"}

    secondary_ptr = struct.unpack('<I', ptr_data)[0]
    if secondary_ptr < 0x80000000 or secondary_ptr > 0x80140000:
        return {"active": True, "bdaddr": bdaddr_str, "error": f"Invalid secondary ptr: 0x{secondary_ptr:08X}"}

    # Read security-critical fields from secondary struct
    result = {
        "active": True,
        "conn_index": conn_index,
        "bdaddr": bdaddr_str,
        "secondary_ptr": f"0x{secondary_ptr:08X}",
    }

    # State byte
    state = read_byte(sock, secondary_ptr + OFF_STATE_BYTE)
    result["state_machine_phase"] = state

    # Encryption key size
    key_size = read_byte(sock, secondary_ptr + OFF_KEY_SIZE)
    result["enc_key_size"] = key_size

    # Encryption enabled
    enc_enabled = read_byte(sock, secondary_ptr + OFF_ENC_ENABLED)
    result["enc_enabled"] = enc_enabled

    # Auth state
    auth_state = read_byte(sock, secondary_ptr + OFF_AUTH_STATE)
    result["auth_state"] = auth_state

    # Secure Connections flag
    sc_data = read4(sock, secondary_ptr + OFF_SC_FLAG)
    if sc_data:
        result["secure_connections"] = sc_data[0]

    # Key material source (16 bytes at +0x02)
    key_src = read_bytes(sock, secondary_ptr + OFF_KEY_MATERIAL_SRC, 16)
    result["key_material_src"] = key_src

    # Key material copy (16 bytes at +0x51)
    key_copy = read_bytes(sock, secondary_ptr + OFF_KEY_MATERIAL_COPY, 16)
    result["key_material_copy"] = key_copy

    # Pairing stage
    pairing = read_byte(sock, secondary_ptr + OFF_PAIRING_STAGE)
    result["pairing_stage"] = pairing

    return result


def format_result(r):
    """Format inspection result for display."""
    if not r.get("active"):
        return f"  Slot {r.get('conn_index', '?')}: EMPTY (no active connection)"

    if "error" in r:
        return f"  Slot {r['conn_index']}: {r['bdaddr']} — ERROR: {r['error']}"

    lines = []
    lines.append(f"  Slot {r['conn_index']}: {r['bdaddr']}")
    lines.append(f"    Secondary struct: {r['secondary_ptr']}")
    lines.append(f"    State machine phase: 0x{r.get('state_machine_phase', 0):02X}")
    lines.append(f"    Auth state: 0x{r.get('auth_state', 0):02X}")
    lines.append(f"    Pairing stage: 0x{r.get('pairing_stage', 0):02X}")

    # Encryption analysis
    enc = r.get('enc_enabled', 0)
    key_size = r.get('enc_key_size', 0)
    sc = r.get('secure_connections', 0)

    enc_str = "YES" if enc else "NO"
    sc_str = "YES" if sc else "NO"
    lines.append(f"    Encryption: {enc_str} (key_size={key_size} bytes)")
    lines.append(f"    Secure Connections: {sc_str}")

    # KNOB vulnerability check
    if enc and key_size == 1:
        lines.append(f"    [!!!] KNOB VULNERABLE — 1-byte encryption key!")
    elif enc and key_size < 7:
        lines.append(f"    [!!] WEAK ENCRYPTION — key_size={key_size} (< 7 bytes)")
    elif enc and key_size >= 7:
        lines.append(f"    [OK] Encryption key size adequate ({key_size} bytes)")

    # Key material
    key_src = r.get('key_material_src', b'\x00' * 16)
    key_copy = r.get('key_material_copy', b'\x00' * 16)

    if any(b != 0 for b in key_src):
        lines.append(f"    Key material (src  +0x02): {key_src.hex()}")
    if any(b != 0 for b in key_copy):
        lines.append(f"    Key material (copy +0x51): {key_copy.hex()}")
        if all(b != 0 for b in key_copy[:4]):
            lines.append(f"    [!] NON-ZERO KEY MATERIAL — possible link key!")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description="RTL8761B Encryption State Inspector")
    parser.add_argument("--conn", type=int, default=-1, help="Connection slot (0-11, default: scan all)")
    parser.add_argument("--watch", action="store_true", help="Continuous monitoring")
    parser.add_argument("--interval", type=int, default=3, help="Watch interval (seconds)")
    args = parser.parse_args()

    ctrl = find_realtek_device()
    if ctrl is None:
        print("[!] No Realtek device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)
    print("[+] Connected to DarkFirmware dongle")

    slots = [args.conn] if args.conn >= 0 else range(12)

    if args.watch:
        print(f"[*] Watching {'slot ' + str(args.conn) if args.conn >= 0 else 'all slots'} every {args.interval}s...")
        try:
            while True:
                ts = time.strftime("%H:%M:%S")
                print(f"\n[{ts}] Encryption State:")
                for slot in slots:
                    r = inspect_connection(sock, slot)
                    if r.get("active"):
                        print(format_result(r))
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Stopped")
    else:
        print("[*] Encryption State Inspection:")
        print("=" * 60)
        found_active = False
        for slot in slots:
            r = inspect_connection(sock, slot)
            if r.get("active"):
                found_active = True
                print(format_result(r))
                print()
        if not found_active:
            print("  No active connections found.")
            print("  Connect to a target first, then run this tool.")
        print("=" * 60)


if __name__ == "__main__":
    main()
