#!/usr/bin/env python3
"""DarkFirmware Initialization — call after firmware download to activate all hooks.

Blue-Tap integration: import this module and call `init_darkfirmware(sock)` after
flashing the DarkFirmware binary. This writes 2 backup pointers to RAM that the
Hook 3/4 shims need to chain back to the original handlers.

The DarkFirmware binary contains:
  PERSISTENT (survive USB reset when firmware at /lib/firmware/rtl_bt/rtl8761bu_fw.bin):
    - Hook 1: HCI CMD handler (LMP injection via VSC 0xFE22)
    - Hook 2: LMP RX handler (full logging + in-flight modification modes 0-5)
    - Hook 3 code: tLC_TX shim (ASM present, pointer patched in binary)
    - Hook 4 code: tLC_RX shim (ASM present, pointer patched in binary)
    - 28-byte oversize LMP, dynamic conn index, opcode-selective drop, etc.

  REQUIRES RUNTIME INIT (2 memory writes, <10ms):
    - backup_addr_3: original tLC_TX handler (0x80042421) at 0x80133FF4
    - backup_addr_4: original tLC_RX handler (0x80042189) at 0x80133FEC
    These are needed because the firmware's boot process re-initializes the
    tLC_TX/tLC_RX pointers from ROM AFTER patch loading, but the shim code
    needs to know where to chain back to.

Usage in Blue-Tap:
    from darkfirmware_init import init_darkfirmware
    sock = UsbBluetoothSocket(controller)
    # ... flash firmware via download_patches() ...
    init_darkfirmware(sock)  # <10ms, activates all 4 hooks
"""

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

class HCI_Cmd_Complete_VSC(Packet):
    name = 'VSC complete'
    fields_desc = [XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3f, ocf=0x0062)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc61)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC, opcode=0xfc62)


# Constants
BACKUP_ADDR_3 = 0x80133FF4       # Where Hook 3 shim reads original tLC_TX address
BACKUP_ADDR_4 = 0x80133FEC       # Where Hook 4 shim reads original tLC_RX address
ORIGINAL_LC_TX = 0x80042421      # ROM assoc_w_tLC_TX (+1 ISA bit)
ORIGINAL_LC_RX = 0x80042189      # ROM assoc_w_tLC_RX (+1 ISA bit)
HOOK1_CHECK_ADDR = 0x80133FFC    # Hook 1 backup — should be 0x8010D891 if DarkFirmware active
HOOK1_EXPECTED = 0x8010D891


def _write(sock, address, value):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(
        address=address, data_to_write=value)
    resp = sock.sr1(pkt, verbose=0, timeout=2)
    return (HCI_Event_Command_Complete in resp and
            resp[HCI_Event_Command_Complete].status == 0)


def _read(sock, address):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=address)
    resp = sock.sr1(pkt, verbose=0, timeout=2)
    if HCI_Event_Command_Complete in resp and resp[HCI_Event_Command_Complete].status == 0:
        data = resp.data
        return int.from_bytes(data[:4], 'little') if isinstance(data, (bytes, bytearray)) else data
    return None


def init_darkfirmware(sock, verbose=True):
    """Initialize DarkFirmware hooks after firmware download.

    Must be called AFTER download_patches() completes.
    Writes 2 backup pointers to RAM (<10ms).

    Returns True if all hooks verified active.
    """
    # Verify DarkFirmware is loaded
    hook1_val = _read(sock, HOOK1_CHECK_ADDR)
    if hook1_val != HOOK1_EXPECTED:
        if verbose:
            print(f"[!] DarkFirmware not detected (Hook 1 backup = 0x{hook1_val:08x}, "
                  f"expected 0x{HOOK1_EXPECTED:08x})")
        return False

    # Write backup pointers for Hook 3 and Hook 4
    ok3 = _write(sock, BACKUP_ADDR_3, ORIGINAL_LC_TX)
    ok4 = _write(sock, BACKUP_ADDR_4, ORIGINAL_LC_RX)

    if verbose:
        print(f"[+] DarkFirmware init: backup_addr_3={'OK' if ok3 else 'FAIL'}, "
              f"backup_addr_4={'OK' if ok4 else 'FAIL'}")

    # Verify all 4 hooks
    results = {
        "hook1_hci_cmd": hook1_val == HOOK1_EXPECTED,
        "hook2_lmp_rx": _read(sock, 0x80133FF8) == 0x8010DFB1,
        "hook3_lc_tx_backup": _read(sock, BACKUP_ADDR_3) == ORIGINAL_LC_TX,
        "hook4_lc_rx_backup": _read(sock, BACKUP_ADDR_4) == ORIGINAL_LC_RX,
    }

    if verbose:
        for name, ok in results.items():
            print(f"  {name}: {'OK' if ok else 'FAIL'}")

    return all(results.values())


if __name__ == "__main__":
    import usbbluetooth
    from scapy_usbbluetooth import UsbBluetoothSocket

    controllers = usbbluetooth.list_controllers()
    ctrl = None
    for c in controllers:
        if c.vendor_id == 0x2357 and c.product_id == 0x0604:
            ctrl = c
            break
        if c.vendor_id == 0x0bda and c.product_id in (0xa728, 0xa729):
            ctrl = c
            break

    if not ctrl:
        print("[!] No Realtek device found")
        exit(1)

    sock = UsbBluetoothSocket(ctrl)
    ok = init_darkfirmware(sock)
    print(f"\nDarkFirmware init: {'SUCCESS' if ok else 'FAILED'}")
