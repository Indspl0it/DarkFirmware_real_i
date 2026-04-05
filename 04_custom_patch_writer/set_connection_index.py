#!/usr/bin/env python3
"""Set the LMP injection connection index on a DarkFirmware-patched RTL8761B.

Uses VSC 0xFC62 (memory write) to patch the 'li $a0, N' instruction in RAM,
changing which ACL connection slot send_LMP_reply() targets.

Usage:
    sudo python3 set_connection_index.py [INDEX]

    INDEX: 0-11 (default: 0). The big_ol_struct array slot for the target connection.

Example:
    sudo python3 set_connection_index.py 0    # Target first connection (default)
    sudo python3 set_connection_index.py 1    # Target second connection
"""

import sys
import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete

# RAM address of the immediate byte in 'li $a0, N' instruction
# This is the connection index passed to send_LMP_reply()
CONN_INDEX_RAM_ADDR = 0x8011167A
CONN_INDEX_VERIFY_BYTE = 0x6C  # Next byte should be 0x6C (li $a0 opcode)
MAX_CONN_INDEX = 11  # RTL8761B supports 12 connection slots (0-11)

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000)]

class HCI_Cmd_VSC_Realtek_Write_Mem(Packet):
    name = "Realtek Write Memory"
    fields_desc = [ByteField("size", 0x20), XLEIntField("address", 0x80000000),
                   XLEIntField("data_to_write", 0x33221100)]

class HCI_Cmd_Complete_VSC_Realtek_Read_Mem(Packet):
    name = 'Realtek Read Memory complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

class HCI_Cmd_Complete_VSC_Realtek_Write_Mem(Packet):
    name = 'Realtek Write Memory complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3f, ocf=0x0062)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Read_Mem, opcode=0xfc61)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Write_Mem, opcode=0xfc62)


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


def read_mem(socket, address):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=address)
    response = socket.sr1(pkt, verbose=0)
    if HCI_Event_Command_Complete not in response or response[HCI_Event_Command_Complete].status != 0:
        return None
    return response.data


def write_mem(socket, address, data):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(address=address, data_to_write=data)
    response = socket.sr1(pkt, verbose=0)
    if HCI_Event_Command_Complete not in response or response[HCI_Event_Command_Complete].status != 0:
        return False
    return True


def main():
    index = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    if index < 0 or index > MAX_CONN_INDEX:
        print(f"[!] Connection index must be 0-{MAX_CONN_INDEX}, got {index}")
        sys.exit(1)

    controller = find_realtek_device()
    if controller is None:
        print("[!] No Realtek device found")
        sys.exit(1)

    socket = UsbBluetoothSocket(controller)

    # Read current value
    data = read_mem(socket, CONN_INDEX_RAM_ADDR)
    if data is None:
        print("[!] Failed to read memory")
        sys.exit(1)
    current = data[0] if isinstance(data, (bytes, bytearray)) else int.from_bytes(data, 'little') & 0xFF
    verify = data[1] if isinstance(data, (bytes, bytearray)) else (int.from_bytes(data, 'little') >> 8) & 0xFF
    print(f"[*] Current connection index: {current} (verify byte: 0x{verify:02x})")

    if verify != CONN_INDEX_VERIFY_BYTE:
        print(f"[!] Verify byte mismatch! Expected 0x{CONN_INDEX_VERIFY_BYTE:02x}, got 0x{verify:02x}")
        print("[!] DarkFirmware may not be loaded or address is wrong")
        sys.exit(1)

    # Write new value (4-byte write: [new_index, 0x6c, ...])
    # Read full 4 bytes, modify just the first byte, write back
    full_val = int.from_bytes(data, 'little') if isinstance(data, (bytes, bytearray)) else data
    new_val = (full_val & 0xFFFFFF00) | index
    if not write_mem(socket, CONN_INDEX_RAM_ADDR, new_val):
        print("[!] Failed to write memory")
        sys.exit(1)

    # Verify
    data = read_mem(socket, CONN_INDEX_RAM_ADDR)
    new_current = data[0] if isinstance(data, (bytes, bytearray)) else int.from_bytes(data, 'little') & 0xFF
    if new_current == index:
        print(f"[+] Connection index set to {index}")
    else:
        print(f"[!] Verification failed: expected {index}, got {new_current}")
        sys.exit(1)


if __name__ == "__main__":
    main()
