# What are these?

* **`RTL8761B_usbbluetooth_Patch_Writer.py`** - python3 script which uses `scapy-usbbluetooth` to send HCI Vendor-Specific Commands (VSC) to Realtek RTL8761B\*-based chips. The VSCs download a customized ephemeral firmware (meaning it's removed at power reset.) The source code for the main custom code is given in [`RTL8761B_patch_modification.asm`](../custom_patch_src_asm/RTL8761B_patch_modification.asm)), and the compiled bytes are placed in the `g_poc_buf[]` list in this code. This code is also responsible for inserting a small MIPS16e inline hook in the original Realtek patches code, which redirects control flow to `_start_install_fptrs` in [`RTL8761B_patch_modification.asm`](../custom_patch_src_asm/RTL8761B_patch_modification.asm)), so that the main custom code is invoked at runtime after the patches are downloaded. This script also sends some memory-read VSCs to confirm that the inlined hook worked, and `_start_install_fptrs` was invoked successfully (in which case the main code, `_installed_fptr_1` & `_installed_fptr_2` should be invoked successfully later.)
* **`rtl8761bu_fw.bin`** - This is the "0xd922" version (based on what it updates the LMP subversion to) of the Realtek firmware for RTL8761BU\* based USB-interfacing chips, which ships with Ubuntu 24.04. It is loaded into a buffer in `RTL8761B_usbbluetooth_Patch_Writer.py` and then customized to insert a hook that redirects control flow to the custom code provided in `RTL8761B_usbbluetooth_Patch_Writer.py`.
* **`rtl8761b_config_set_bdaddr_only_1337.bin`** - This is a Realtek configuration file which sets the device BDADDR to 13:37:13:37:13:37. It is potentially used by `RTL8761B_usbbluetooth_Patch_Writer.py`.
* **`rtl8761b_config_set_bdaddr_only_1338.bin`** - This is a Realtek configuration file which sets the device BDADDR to 13:38:13:38:13:38. It is potentially used by `RTL8761B_usbbluetooth_Patch_Writer.py`.

* **`RTL8761B_usbbluetooth_Memory_Reader.py`** - This is a script to allow you to read an arbitrary range of memory from the RTL8761B\* memory space, and output it to a file named `f"rtl8761b_dump_0x{begin_addr:08x}_0x{end_addr:08x}.bin"` in Python format string syntax (e.g. `rtl8761b_dump_0x80080000_0x80090000.bin`). NOTE: The memory controller seems to default to returning 0xdeadbeef for invalid memory ranges.


# Linux

Tested on Ubuntu 24.04 x86 and ARM (both in VMware on macOS.)

## Install prerequisite software:

```
sudo apt update
sudo apt install -y python3 python3-venv
cd ~/darkfirmware_real_i/04_custom_patch_writer
python3 -m venv ./venv
source ./venv/bin/activate
pip3 install scapy-usbbluetooth==0.1.0 usbbluetooth==0.1.3
```

### udev rules

It is recommended to create udev rules for your specific USB device as described [here](https://github.com/antoniovazquezblanco/usbbluetooth/blob/main/doc/README.md#linux), so that you don't need to run the script as root. Otherwise, if you just want to run as root, you'll need to do `sudo pip3 install scapy-usbbluetooth --break-system-packages`.

So a short form would be `sudo nano /etc/udev/rules.d/99-usbbluetooth.rules`. Then add the following content (these being some of the common USB VID:DID (Vendor ID & Device ID) combos I see on my devices. Use `lsusb` to find if they match your device, and if not, add an entry for yours.)

```
SUBSYSTEM=="usb", ATTR{idVendor}=="2550", ATTR{idProduct}=="8761", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="0BDA", ATTR{idProduct}=="A728", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="0BDA", ATTR{idProduct}=="A729", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="2357", ATTR{idProduct}=="0604", MODE="0666"
```

Then save and exit, and run `sudo udevadm control --reload-rules && sudo udevadm trigger`.

## Run tools

### `RTL8761B_usbbluetooth_Memory_Reader.py`

As unprivileged user (assuming you've set the necessary udev rules)

* `python3 ./RTL8761B_usbbluetooth_Memory_Reader.py` - to dump from `begin_addr` (0x8011160c by default), to `end_addr` (`begin_addr + 0x200` by default.) and output the bytes to `f"rtl8761b_dump_0x{begin_addr:08x}_0x{end_addr:08x}.bin"` in python format string format (e.g. `rtl8761b_dump_0x8011160c_0x8011180c.bin`)

On success you should see something like the following:

```
(venv) user@B2VM:~/darkfirmware_real_i/04_custom_patch_writer$ python3 ./RTL8761B_usbbluetooth_Memory_Reader.py
[+] Locating a Realtek device...
[+] Opening socket...
[+] Opening output file...
[+] Reading @ 0x8011160c
[+] Reading @ 0x80111610
[+] Reading @ 0x80111614
...
[+] Reading @ 0x80111808
[+] Reading memory...
(venv) user@B2VM:~/darkfirmware_real_i/04_custom_patch_writer$ 
```

***Important Note!:*** *apparently* virtualized USB controllers, such as VMware uses, make the VSCs to the USB BT dongles go *really slow!* Things are much faster on bare-metal systems, but there are still some delays for unknown reasons. A command on bare-metal that takes 3s may take 30-300s on a virtualized system!

### 🌟`RTL8761B_usbbluetooth_Patch_Writer.py`🌟

For this tool's patching to take effect, the Linux system's Realtek USB driver needs to be disabled, because this is somehow resetting the chip after firmware update, and breaking the downloaded patches. Disable it as follows:

```
sudo nano /etc/modprobe.d/blacklist.conf
```

Add the following lines at the end of the file:

```
blacklist btrtl
blacklist btusb
```

Then save and reboot. Confirmed `lsmod | grep rtl` shows no output.

Then to run the command, execute the following:

* `python3 ./RTL8761B_usbbluetooth_Patch_Writer.py` - to download the custom firmware stored in `g_poc_buf` + the configuration stored in `rtl8761b_config_set_bdaddr_only_1337.bin` or `rtl8761b_config_set_bdaddr_only_1338.bin` to the dongle. Note: the code is set up to use the `rtl8761b_config_set_bdaddr_only_1337.bin` config (and thus a 13:37:13:37:13:37 BDADDR) for a device that matches (VID,DID) == (0x0bda,0xa729) by default, and it uses `rtl8761b_config_set_bdaddr_only_1338.bin` (and thus a 13:38:13:38:13:38 BDADDR) for any other device. But you can of course change this to match on other VID:DIDs, or hex edit the configs to use different BDADDRs.

```
(venv) user@B2VM:~/darkfirmware_real_i/04_custom_patch_writer$ python3 ./RTL8761B_usbbluetooth_Patch_Writer.py 
[+] Locating a Realtek device...
[+] Opening socket...
[+] Resetting the controller...
Address that should be our hook1 fptr: 0x80014181
HCI Version: 0x0a
HCI Revision: 0xdfc6
LMP Version: 0x0a
Manufacturer: 0x5d
LMP Subversion: 0xd922
Patch version: 0xdfc6d922
Number of chip revisions in patch: 2
Selected patch start: 0x00003780, end: 0x0000ad7c
POC Start Address = 0x8011160d
First {patch_buf_insert_size} bytes of final_full_data before patch: 0891079000ef0563
First {patch_buf_insert_size} bytes of final_full_data after patch: 01b380eb0d161180
Number of chip revisions in patch: 2
Selected patch start: 0x00003780, end: 0x0000ad7c
Wrote 45004 bytes to ./final_patched_poc_fw.bin
Success for patch fragment 0 at offset 0x0000 with length 0xfc
Success for patch fragment 1 at offset 0x00fc with length 0xfc
...
Success for patch fragment 121 at offset 0x771c with length 0xe8
HCI Version: 0x0a
HCI Revision: 0xdfc6
LMP Version: 0x0a
Manufacturer: 0x5d
LMP Subversion: 0xd922
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[+] Code execution confirmed! Expected value 8010d891 found at 0x80133ffc!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[+] Code execution confirmed! Expected value 8010dfb1 found at 0x80133ff8!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[?] Address that should be our hook1 fptr: 0x80111635
[?] Address that should be our hook2 fptr: 0x801116bd

```

***Important Note!:*** *apparently* virtualized USB controllers, such as VMware uses, make the VSCs to the USB BT dongles go *really slow!* Things are much faster on bare-metal systems, but there are still some delays for unknown reasons. A command on bare-metal that takes 3s may take 30-300s on a virtualized system!

**Note:** Only the first application of a patch file after reset is actually applied. If you run the command a second time, it's not actually making any changes. So if you change the code in `g_poc_buf` by changing the code in [`RTL8761B_patch_modification.asm`](../02_custom_patch_src_asm/RTL8761B_patch_modification.asm), you need to reset the dongle before you re-run `RTL8761B_usbbluetooth_Patch_Writer.py`, in order to get the updated code applied.

---

**Additional sanity checking that the patch applied, and the system's realtek driver is disable:**

Before patch applied:

```
(venvX) user@B2VM:~/darkfirmware_real_i/05_XENO_VSC_RX_TX/bumble/tools$ python3 ./rtk_util.py info usb:0bda:a728
Driver:
  ROM:      8761
  Firmware: rtl8761bu_fw.bin
  Config:   rtl8761bu_config.bin
```

After patch applied:

```
(venvX) user@B2VM:~/darkfirmware_real_i/05_XENO_VSC_RX_TX/bumble/tools$ python3 ./rtk_util.py info usb:0bda:a728
Firmware loaded: 0xDFC6D922
```

---

If your output ends with something like the following, instead of the above, it indicates failure:

```
...
[-] Code execution unconfirmed! (Value = 00000000 at 80133ffc)
[-] Code execution unconfirmed! (Value = 00000000 at 80133ff8)
[?] Address that should be our hook1 fptr: 0x8010d891
[?] Address that should be our hook2 fptr: 0x8010dfb1
```

The most likely cause, is that you didn't change the original OS firmware name to make it not found and not applied (or you're using a UART-based system and need to move the other file), or you need to restart the dongle.

---
---

# Windows

Tested on Windows 10 & 11

## Install prerequisite software:

TODO: Update instructions once I have a chance to re-confirm. But essentially it requires using [Zadig](https://zadig.akeo.ie/) to change the loaded BT driver to the "WinUSB" one for the specific BT dongle once plugged in. After that the code can be run from a python environment like CLI or VSCode.

---
Copyright 2025 Dark Mentor LLC - [https://darkmentor.com](https://darkmentor.com)