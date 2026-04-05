"""Shared utilities for DarkFirmware tools.

Provides correct HCI packet handling, device detection, and memory access
functions used by all DarkFirmware Python tools.

Fixes:
  - UsbBluetoothSocket.recv() returns scapy Packet, not bytes.
    All tools must use recv_raw_bytes() instead.
  - Consistent VID/PID detection for all supported Realtek dongles.
  - Correct connection slot size (0x2B8 = 696 bytes from RE).
  - Proper None handling on sr1() timeouts.
"""

import struct
import time

import usbbluetooth
from scapy.compat import raw as scapy_raw
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

# --- HCI Packet Classes ---

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

class HCI_Cmd_Complete_VSC_Read(Packet):
    name = 'Realtek Read Memory complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

class HCI_Cmd_Complete_VSC_Write(Packet):
    name = 'Realtek Write Memory complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

# Register scapy layers (idempotent)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3f, ocf=0x0062)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Xeno_Send_LMP, ogf=0x3f, ocf=0x0222)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Read, opcode=0xfc61)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Write, opcode=0xfc62)

# --- Constants ---

# Supported Realtek Bluetooth dongles
SUPPORTED_DEVICES = [
    (0x0bda, 0xa728),  # ZEXMTE
    (0x0bda, 0xa729),  # Realtek variant
    (0x2c0a, 0x8761),  # Realtek variant
    (0x2550, 0x8761),  # Realtek variant
    (0x2357, 0x0604),  # TP-Link UB500 / StarTech AV53C1
]

# Connection table
BOS_BASE = 0x8012DC50
SLOT_SIZE = 0x2B8  # 696 bytes (confirmed via RE: param_1 * 0x2B8 in decompiled code)
MAX_SLOTS = 12
SECONDARY_PTR_OFFSET = 0x58

# Secondary struct field offsets (from decompiled functions)
OFF_STATE_BYTE = 0x01
OFF_KEY_MATERIAL_SRC = 0x02   # 16 bytes
OFF_PAIRING_STAGE = 0x12
OFF_KEY_SIZE = 0x23           # Negotiated encryption key size (1-16)
OFF_ENC_ENABLED = 0x26        # Encryption enabled boolean
OFF_AUTH_STATE = 0x50
OFF_KEY_MATERIAL_COPY = 0x51  # 16 bytes — link key material
OFF_SC_FLAG = 0x214           # Secure Connections enabled

# Modification control
MOD_FLAG_ADDR = 0x80133FF0
MOD_TABLE_ADDR = 0x80133FE0
AUTO_RESP_TRIGGER_ADDR = 0x80133FD8

# HCI Event markers
MARKER_AAAA = 0x41414141  # RX LMP (Hook 2)
MARKER_TXXX = 0x58585854  # TX LMP (Hook 3)
MARKER_ACLX = 0x584C4341  # TX ACL (Hook 3)
MARKER_RXLC = 0x434C5852  # RX LC (Hook 4)

# LMP opcode names
LMP_OPCODES = {
    0x01: "LMP_NAME_REQ", 0x02: "LMP_NAME_RES", 0x03: "LMP_ACCEPTED",
    0x04: "LMP_NOT_ACCEPTED", 0x07: "LMP_DETACH", 0x08: "LMP_IN_RAND",
    0x09: "LMP_COMB_KEY", 0x0B: "LMP_AU_RAND", 0x0C: "LMP_SRES",
    0x0F: "LMP_ENCRYPTION_MODE_REQ", 0x10: "LMP_ENCRYPTION_KEY_SIZE_REQ",
    0x11: "LMP_START_ENCRYPTION_REQ", 0x12: "LMP_STOP_ENCRYPTION_REQ",
    0x13: "LMP_SWITCH_REQ", 0x1D: "LMP_SETUP_COMPLETE",
    0x25: "LMP_VERSION_REQ", 0x26: "LMP_VERSION_RES",
    0x27: "LMP_FEATURES_REQ", 0x28: "LMP_FEATURES_RES",
    0x36: "LMP_ENC_KEY_SIZE_MASK_REQ", 0x37: "LMP_ENC_KEY_SIZE_MASK_RES",
    0x7F: "LMP_ESCAPE_4",
}


# --- Device Detection ---

def find_realtek_device():
    """Find a supported Realtek Bluetooth controller."""
    controllers = usbbluetooth.list_controllers()
    for c in controllers:
        if (c.vendor_id, c.product_id) in SUPPORTED_DEVICES:
            return c
    return None


# --- Raw HCI Receive (CRITICAL FIX) ---

def recv_raw_bytes(sock, timeout_ms=1000):
    """Receive raw HCI bytes from the USB socket.

    UsbBluetoothSocket.recv() returns a scapy Packet, NOT raw bytes.
    This function gets the actual bytes by calling recv_raw() directly.

    Returns: raw bytes (starting with 0x04 for events, 0x02 for ACL) or None.
    """
    try:
        cls, data, ts = sock.recv_raw(timeout_ms)
        if data is None:
            return None
        return bytes(data)
    except Exception:
        return None


def collect_hci_events(sock, timeout_sec=2.0, event_code=0xFF):
    """Collect HCI events as raw bytes, filtering by event code.

    Returns list of event parameter bytes (after the 0x04 type + code + length header).
    """
    events = []
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        raw = recv_raw_bytes(sock, timeout_ms=500)
        if raw is None:
            continue
        # HCI Event format: [0x04] [event_code] [param_len] [params...]
        if len(raw) >= 3 and raw[0] == 0x04 and raw[1] == event_code:
            param_len = raw[2]
            params = raw[3:3+param_len]
            events.append(params)
    return events


def collect_lmp_logs(sock, timeout_sec=2.0):
    """Collect DarkFirmware LMP log events (HCI Event 0xFF with known markers).

    Returns list of raw event parameter bytes that start with a known marker.
    """
    logs = []
    for params in collect_hci_events(sock, timeout_sec, event_code=0xFF):
        if len(params) >= 4:
            marker = struct.unpack_from("<I", params, 0)[0]
            if marker in (MARKER_AAAA, MARKER_TXXX, MARKER_ACLX, MARKER_RXLC):
                logs.append(params)
    return logs


# --- Memory Access ---

def read_mem(sock, addr):
    """Read 4 bytes from controller memory. Returns bytes(4) or None."""
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=addr)
    try:
        resp = sock.sr1(pkt, verbose=0, timeout=2)
        if resp is None:
            return None
        if HCI_Event_Command_Complete not in resp:
            return None
        if resp[HCI_Event_Command_Complete].status != 0:
            return None
        data = resp.data
        if isinstance(data, (bytes, bytearray)):
            return bytes(data[:4])
        elif isinstance(data, int):
            return data.to_bytes(4, 'little')
        return None
    except Exception:
        return None


def write_mem(sock, addr, value):
    """Write 4 bytes to controller memory. Returns True on success."""
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(
        address=addr, data_to_write=value)
    try:
        resp = sock.sr1(pkt, verbose=0, timeout=2)
        if resp is None:
            return False
        if HCI_Event_Command_Complete not in resp:
            return False
        return resp[HCI_Event_Command_Complete].status == 0
    except Exception:
        return False


def read_bytes(sock, addr, count):
    """Read N bytes from controller memory (4-byte aligned reads)."""
    data = bytearray()
    for off in range(0, count, 4):
        chunk = read_mem(sock, addr + off)
        data.extend(chunk if chunk else b'\x00\x00\x00\x00')
    return bytes(data[:count])


def read_byte(sock, addr):
    """Read a single byte from controller memory."""
    data = read_mem(sock, addr & ~3)
    if data:
        return data[addr & 3]
    return None


def write_byte(sock, addr, val):
    """Write a single byte using read-modify-write on 4-byte aligned word."""
    aligned = addr & ~3
    data = read_mem(sock, aligned)
    if not data:
        return False
    word = struct.unpack('<I', data)[0]
    shift = (addr & 3) * 8
    mask = ~(0xFF << shift) & 0xFFFFFFFF
    new_word = (word & mask) | ((val & 0xFF) << shift)
    return write_mem(sock, aligned, new_word)


# --- LMP Operations ---

def send_lmp(sock, conn_index, lmp_data):
    """Send an LMP packet via VSC 0xFE22.

    Args:
        conn_index: Connection slot (0-11)
        lmp_data: Raw LMP bytes (opcode + params, NOT encoded with TID)
                  The firmware encodes the TID automatically.

    Format sent to firmware: [conn_index:1B] [lmp_data:NB]
    """
    payload = bytes([conn_index & 0xFF]) + bytes(lmp_data)
    pkt = HCI_Hdr() / HCI_Command_Hdr(ogf=0x3f, ocf=0x0222) / \
          HCI_Cmd_VSC_Xeno_Send_LMP(data=payload)
    try:
        resp = sock.sr1(pkt, verbose=0, timeout=3)
        return resp is not None
    except Exception:
        return False


def send_raw_acl(sock, handle, l2cap_data, pb=2, bc=0):
    """Send raw HCI ACL data via USB, bypassing the host BT stack.

    The controller encrypts and transmits whatever we provide.
    No L2CAP validation occurs — enables malformed frame injection.

    Args:
        handle: ACL connection handle (12 bits)
        l2cap_data: Raw L2CAP frame bytes (header + payload)
        pb: Packet boundary flag (2 = first automatically flushable)
        bc: Broadcast flag (0 = point-to-point)
    """
    handle_flags = (handle & 0xFFF) | ((pb & 0x3) << 12) | ((bc & 0x3) << 14)
    data_len = len(l2cap_data)
    # Full HCI ACL packet: [type=0x02] [handle_flags:2B LE] [data_len:2B LE] [data]
    hci_pkt = struct.pack('<BHH', 0x02, handle_flags, data_len) + l2cap_data
    try:
        sock._dev.write(hci_pkt)
        return True
    except Exception as e:
        return False
