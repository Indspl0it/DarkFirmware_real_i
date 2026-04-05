#!/usr/bin/env python3
"""L2CAP Fuzzer — inject malformed L2CAP frames below the host stack.

Sends raw HCI ACL data packets directly to the controller via USB,
bypassing BlueZ's L2CAP stack entirely. The controller encrypts and
transmits whatever we provide — no L2CAP validation occurs.

Combined with DarkFirmware's ACL monitoring hooks (ACLX/RXLC markers),
we can see both sent and received ACL data.

Usage:
    sudo python3 l2cap_fuzzer.py --handle 0x0040 --mode test
    sudo python3 l2cap_fuzzer.py --handle 0x0040 --mode fuzz [--count 100]
    sudo python3 l2cap_fuzzer.py --handle 0x0040 --mode inject --cid 0x0001 --data "0200..."

Modes:
    test    Send a valid L2CAP echo request to verify injection works
    fuzz    Send malformed L2CAP frames (truncated, oversized, bad CID, etc.)
    inject  Send a specific raw L2CAP frame

Connection handle: get from `hcitool con` (e.g., 0x0040)

Requires: DarkFirmware loaded. Active ACL connection to target.
"""

import sys
import os
import struct
import time
import argparse

import usbbluetooth
from darkfirmware_utils import find_realtek_device as _find_device, send_raw_acl as _send_acl
from scapy_usbbluetooth import UsbBluetoothSocket

# HCI ACL Data packet format:
# [0x02] [handle_lo] [handle_hi | PB<<4 | BC<<6] [data_len_lo] [data_len_hi] [data...]
# PB (Packet Boundary): 0=reserved, 1=continuing, 2=first_auto_flush, 3=first_no_auto
# BC (Broadcast): 0=point_to_point, 1=active_broadcast, 2=piconet_broadcast

# L2CAP header:
# [length:2B LE] [CID:2B LE] [payload...]
# CID 0x0001 = L2CAP Signaling
# CID 0x0003 = AMP Manager
# CID 0x0005 = LE L2CAP Signaling
# CID 0x0006 = SMP
# CID 0x0040+ = Dynamic channels


def find_device():
    return _find_device()


def build_hci_acl(handle, pb=2, bc=0, l2cap_data=b""):
    """Build a raw HCI ACL data packet."""
    # HCI header
    handle_flags = (handle & 0xFFF) | ((pb & 0x3) << 12) | ((bc & 0x3) << 14)
    data_len = len(l2cap_data)
    hci_hdr = struct.pack('<BHH', 0x02, handle_flags, data_len)
    return hci_hdr + l2cap_data


def build_l2cap(cid, payload=b""):
    """Build an L2CAP frame (header + payload)."""
    length = len(payload)
    return struct.pack('<HH', length, cid) + payload


def build_l2cap_echo_req(identifier=0x01, data=b"PING"):
    """Build L2CAP Echo Request (signaling CID 0x0001, code 0x08)."""
    # L2CAP signaling: [code:1B] [identifier:1B] [length:2B LE] [data...]
    sig = struct.pack('<BBH', 0x08, identifier, len(data)) + data
    return build_l2cap(0x0001, sig)


# Fuzz test cases
FUZZ_TESTS = [
    {
        "name": "zero_length_l2cap",
        "desc": "L2CAP with length=0",
        "l2cap": struct.pack('<HH', 0, 0x0001),  # length=0, CID=signaling
    },
    {
        "name": "max_length_l2cap",
        "desc": "L2CAP claiming 0xFFFF length with short payload",
        "l2cap": struct.pack('<HH', 0xFFFF, 0x0001) + b"A" * 4,
    },
    {
        "name": "bad_cid_zero",
        "desc": "L2CAP with CID=0 (reserved/invalid)",
        "l2cap": build_l2cap(0x0000, b"test"),
    },
    {
        "name": "bad_cid_0002",
        "desc": "L2CAP with CID=0x0002 (connectionless reception)",
        "l2cap": build_l2cap(0x0002, b"\x00\x40test"),  # PSM + data
    },
    {
        "name": "bad_cid_ffff",
        "desc": "L2CAP with CID=0xFFFF (max)",
        "l2cap": build_l2cap(0xFFFF, b"test"),
    },
    {
        "name": "smp_on_classic",
        "desc": "SMP (CID 0x0006) on Classic BR/EDR connection",
        "l2cap": build_l2cap(0x0006, b"\x01" + b"\x00" * 6),  # Pairing Request
    },
    {
        "name": "truncated_l2cap_header",
        "desc": "Only 2 bytes of L2CAP header (missing CID)",
        "l2cap": struct.pack('<H', 4),  # length only, no CID
    },
    {
        "name": "signaling_bad_code",
        "desc": "L2CAP signaling with invalid command code 0xFF",
        "l2cap": build_l2cap(0x0001, struct.pack('<BBH', 0xFF, 0x01, 0)),
    },
    {
        "name": "signaling_truncated",
        "desc": "L2CAP signaling with truncated header",
        "l2cap": build_l2cap(0x0001, b"\x01"),  # Only code byte
    },
    {
        "name": "echo_oversized",
        "desc": "L2CAP Echo Request with 500 bytes of data",
        "l2cap": build_l2cap_echo_req(data=b"A" * 500),
    },
    {
        "name": "info_req_invalid_type",
        "desc": "L2CAP Information Request with invalid info type 0xFFFF",
        "l2cap": build_l2cap(0x0001, struct.pack('<BBH H', 0x0A, 0x01, 2, 0xFFFF)),
    },
    {
        "name": "conn_req_psm_zero",
        "desc": "L2CAP Connection Request with PSM=0 (invalid)",
        "l2cap": build_l2cap(0x0001, struct.pack('<BBH HH', 0x02, 0x01, 4, 0x0000, 0x0040)),
    },
    {
        "name": "conn_req_psm_sdp",
        "desc": "L2CAP Connection Request for SDP (PSM 0x0001)",
        "l2cap": build_l2cap(0x0001, struct.pack('<BBH HH', 0x02, 0x01, 4, 0x0001, 0x0040)),
    },
    {
        "name": "config_req_no_conn",
        "desc": "L2CAP Config Request for nonexistent channel",
        "l2cap": build_l2cap(0x0001, struct.pack('<BBH HH', 0x04, 0x01, 4, 0x0040, 0x0000)),
    },
    {
        "name": "disconnect_req_invalid",
        "desc": "L2CAP Disconnect Request for invalid DCID/SCID",
        "l2cap": build_l2cap(0x0001, struct.pack('<BBH HH', 0x06, 0x01, 4, 0xFFFF, 0xFFFF)),
    },
    {
        "name": "negative_length",
        "desc": "L2CAP length field with length > actual data (underflow check)",
        "l2cap": struct.pack('<HH', 100, 0x0001) + b"A" * 4,  # Claims 100, only 4
    },
]


def send_raw_acl(sock, handle, l2cap_data, pb=2, bc=0):
    """Send raw HCI ACL data via USB, bypassing the host BT stack.

    Uses Controller.write() which handles ACL data (type 0x02) by writing
    to the ACL OUT endpoint. The controller encrypts and transmits as-is.
    """
    pkt = build_hci_acl(handle, pb, bc, l2cap_data)
    try:
        # Controller.write() checks pkt[0] for type: 0x01=CMD, 0x02=ACL
        # For type 0x02, it writes to _ep_acl_out endpoint
        sock._dev.write(pkt)
        return True
    except Exception as e:
        print(f"  [!] ACL send failed: {e}")
        return False


def check_alive(sock):
    """Check if controller is still responsive via HCI command."""
    from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Read_BD_Addr
    try:
        pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Read_BD_Addr()
        resp = sock.sr1(pkt, verbose=0, timeout=2)
        return resp is not None
    except Exception:
        return False


def mode_test(sock, handle):
    """Send a valid L2CAP echo request to verify injection works."""
    print("[*] Sending L2CAP Echo Request...")
    l2cap = build_l2cap_echo_req(identifier=0x42, data=b"DarkFirmware")
    print(f"    Handle: 0x{handle:04X}")
    print(f"    L2CAP: {l2cap.hex()}")

    ok = send_raw_acl(sock, handle, l2cap)
    print(f"    Send: {'OK' if ok else 'FAILED'}")

    if ok:
        time.sleep(1)
        alive = check_alive(sock)
        print(f"    Controller alive: {'YES' if alive else 'NO'}")
        if alive:
            print("[+] ACL injection working — L2CAP Echo Request sent to target")
        else:
            print("[!] Controller became unresponsive after ACL send")


def mode_fuzz(sock, handle, count=None):
    """Run L2CAP fuzz test cases."""
    tests = FUZZ_TESTS if count is None else FUZZ_TESTS[:count]
    results = []

    print(f"[*] Running {len(tests)} L2CAP fuzz tests against handle 0x{handle:04X}")
    print()

    for test in tests:
        name = test["name"]
        desc = test["desc"]
        l2cap = test["l2cap"]

        print(f"  [{name}] {desc}")
        print(f"    Data ({len(l2cap)}B): {l2cap[:20].hex()}{'...' if len(l2cap) > 20 else ''}")

        ok = send_raw_acl(sock, handle, l2cap)
        time.sleep(0.3)

        alive = check_alive(sock)
        status = "OK" if alive else "CRASH"

        print(f"    Send: {'OK' if ok else 'FAIL'}, Controller: {status}")
        results.append({"name": name, "ok": ok, "alive": alive})

        if not alive:
            print(f"    [!!!] CONTROLLER CRASHED on: {name}")
            break

    print()
    print("=" * 60)
    crashes = [r for r in results if not r.get("alive")]
    print(f"[*] {len(results)} tests run, {len(crashes)} crashes")
    if crashes:
        print(f"    Crashed on: {[r['name'] for r in crashes]}")
    print("=" * 60)

    return results


def mode_inject(sock, handle, cid, data_hex):
    """Inject a specific L2CAP frame."""
    payload = bytes.fromhex(data_hex)
    l2cap = build_l2cap(cid, payload)
    print(f"[*] Injecting L2CAP frame:")
    print(f"    Handle: 0x{handle:04X}")
    print(f"    CID: 0x{cid:04X}")
    print(f"    Payload ({len(payload)}B): {payload.hex()}")
    print(f"    Full L2CAP ({len(l2cap)}B): {l2cap.hex()}")

    ok = send_raw_acl(sock, handle, l2cap)
    print(f"    Send: {'OK' if ok else 'FAILED'}")


def main():
    parser = argparse.ArgumentParser(description="L2CAP Fuzzer (below-HCI injection)")
    parser.add_argument("--handle", type=lambda x: int(x, 0), required=True,
                        help="ACL connection handle (hex, e.g., 0x0040)")
    parser.add_argument("--mode", choices=["test", "fuzz", "inject"], default="test")
    parser.add_argument("--count", type=int, help="Number of fuzz tests")
    parser.add_argument("--cid", type=lambda x: int(x, 0), default=0x0001)
    parser.add_argument("--data", default="", help="Hex payload for inject mode")
    args = parser.parse_args()

    ctrl = find_device()
    if not ctrl:
        print("[!] No device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)
    print(f"[+] Device: VID=0x{ctrl.vendor_id:04x} PID=0x{ctrl.product_id:04x}")

    if args.mode == "test":
        mode_test(sock, args.handle)
    elif args.mode == "fuzz":
        mode_fuzz(sock, args.handle, args.count)
    elif args.mode == "inject":
        mode_inject(sock, args.handle, args.cid, args.data)


if __name__ == "__main__":
    main()
