# By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Reset, HCI_Event_Command_Complete

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Mem"
    fields_desc = [
        ByteField("size", 0x20),
        XLEIntField("address", 0x80000000)
    ]

class HCI_Cmd_Complete_VSC_Realtek_Read_Mem(Packet):
    name = 'Realtek Read Mem complete'
    fields_desc = [
        XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)
    ]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Read_Mem, opcode=0xfc61)


def find_realtek_device():
    controllers = usbbluetooth.list_controllers()
    for c in controllers:
        # Connect to any Realtek device that I've seen so far
        # if (c.vendor_id == 0x0bda and c.product_id == 0xa729): # for when you only want to test with a specific device
        # if (c.vendor_id == 0x2550 and c.product_id == 0x8761):	# for when you only want to test with a specific device
        if( (c.vendor_id == 0x0bda and c.product_id == 0xa728) or \
            (c.vendor_id == 0x0bda and c.product_id == 0xa729) or \
            (c.vendor_id == 0x2c0a and c.product_id == 0x8761) or \
            (c.vendor_id == 0x2550 and c.product_id == 0x8761) or \
            (c.vendor_id == 0x2357 and c.product_id == 0x0604)):
            return c

    return None


def reset(socket):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset()
    response = socket.sr1(pkt, verbose=0)
    if not HCI_Event_Command_Complete in response or response[HCI_Event_Command_Complete].status != 0:
        return False
    return True


def read(socket, address=0x80000000):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=address)
    #pkt.show()
    response = socket.sr1(pkt, verbose=0)
    #response.show()
    if not HCI_Event_Command_Complete in response or response[HCI_Event_Command_Complete].status != 0:
        return None
    return response.data


def main():
    print("[+] Locating a Realtek device...")
    device = find_realtek_device()
    if device is None:
        print("[!] Could not find a suitable device!")
        return

    print("[+] Opening socket...")
    socket = UsbBluetoothSocket(device)

    # "POC Start Address" according to download scripts, -1 for alignment
    begin_addr = 0x8011160c
    # 0x200 to cover all our code + global data
    end_addr = begin_addr + 0x200

    print("[+] Opening output file...")
    with open(f"rtl8761b_dump_0x{begin_addr:08x}_0x{end_addr:08x}.bin", "wb") as f:
        for addr in range(begin_addr, end_addr, 4):
            print(f"[+] Reading @ 0x{addr:08x}")
            data = read(socket, addr)
            if data is None:
                print("[!] Error!")
                break
            f.write(data)

    print("[+] Reading memory...")
    read(socket)


if __name__ == "__main__":
    main()
