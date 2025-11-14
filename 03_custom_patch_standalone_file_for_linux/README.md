# What are these?

* **`rtl8761bu_config_001122334455.bin.zst`** - This is a configuration file which can be used with the stock firmware, to tell it to change only the BT Classic / BLE Public Bluetooth Device Address (BDADDR) to 00:11:22:33:44:55.

* **`rtl8761bu_config_112233445566.bin.zst`** - This is a configuration file which can be used with the stock firmware, to tell it to change only the BT Classic / BLE Public Bluetooth Device Address (BDADDR) to 11:22:33:44:55:66.

* **`DarkFirmware_real_i.bin.zst`** - This is the customized firmware which is output by [`RTL8761B_usbbluetooth_Patch_Writer.py`](../04_custom_patch_writer/RTL8761B_usbbluetooth_Patch_Writer.py) as `final_patched_poc_fw.bin`, compressed with zstd to meet the expectations of Ubuntu 24.04. This file can be simply dropped into `/lib/firmware/rtl_bt/rtl8761bu_fw.bin.zst` to have the custom firmware installed in every RTL8761B\*-based dongle attached to the system.

* **`install_DarkFirmware_real.sh `** - An install script to ease the installation of the `DarkFirmware_real_i.bin.zst` file, on systems that use compressed firmware and those which don't.

* **`uninstall_DarkFirmware_real.sh `** - An uninstall script to ease the installation of the `DarkFirmware_real_i.bin.zst` file, on systems that use compressed firmware and those which don't.

# Installation

**Tested on**:  

 * Ubuntu 24.04 Linux VM on x86-64 & ARM  
 * Raspberry Pi 4b + Raspbian Bookworm x86-64 and Raspbian Trixie x86-32

Assumes this git repo is checked out at ~.

## Set RTL8761B\*-based dongle custom BDADDR only

This file should only be used if you want to leave the Realtek firmware alone, and change only the BT Classic / BLE Public Bluetooth Device Address (BDADDR). This file will have no effect if the full custom firmware below is also present.

(The first line below is to backup a copy of the config, if one already exists, and no backup exists. If a backup already exists, it doesn't overwrite it.)

```
[ -e /lib/firmware/rtl_bt/rtl8761bu_config.bin.zst ] && sudo cp /lib/firmware/rtl_bt/rtl8761bu_config.bin.zst /lib/firmware/rtl_bt/rtl8761bu_config.bin.zst.bak

sudo cp ~/darkfirmware_real_i/02_custom_patch_standalone_file_for_linux/rtl8761bu_config_00112233445.bin.zst /lib/firmware/rtl_bt/
```

Detach and reattach an RTL8761B\*-based dongle, and it should show a BDADDR of 00:11:22:33:44:55 in the output of `hciconfig`.

```
user@BTVM:~$ hciconfig 
hci0:	Type: Primary  Bus: USB
	BD Address: 00:11:22:33:44:55  ACL MTU: 1021:6  SCO MTU: 255:12
	UP RUNNING 
	RX bytes:1686 acl:0 sco:0 events:185 errors:0
	TX bytes:33933 acl:0 sco:0 commands:186 errors:0
```

***Note:*** This applies to all RTL8761B\*-based dongles, so if you attach 2 or more, they will have the same BDADDR. This could cause some problems for some tools, so you may want to keep multiple files on hand and switch between them to specify multiple BDADDRs. That is why we have provided two example configuration files. See below for how to create a different file with a different BDADDR.

### Picking your own BDADDR

Install zstd with `sudo apt install zstd`. Then copy the bash script `set_BDADDR.sh` in this folder to your filesystem and run `chmod +x set_BDADDR.sh` to make it executable.

You can now run the script as `./set_BDADDR.sh 00:22:44:66:88:AA` and after you detach and reattach the RTL8761B\*-based dongle, you should see the BDADDR set to 00:22:44:66:88:AA in the output of `hciconfig`.

```
user@BTVM:~$ hciconfig 
hci0:	Type: Primary  Bus: USB
	BD Address: 00:22:44:66:88:AA  ACL MTU: 1021:6  SCO MTU: 255:12
	UP RUNNING 
	RX bytes:1686 acl:0 sco:0 events:185 errors:0
	TX bytes:33933 acl:0 sco:0 commands:186 errors:0
```

## 🌟Custom LMP sending/logging firmware🌟

`install_DarkFirmware_real.sh` can be used to install the firmware contained in `DarkFirmware_real_i.bin.zst` on both systems that use compressed firmware (i.e. it will write to `/lib/firmware/rtl_bt/rtl8761bu_fw.bin.zst`) and those which don't (i.e. it will write it to `/lib/firmware/rtl_bt/rtl8761bu_fw.bin`.)

**Example of what's shown on a a system using compressed firmware**: (e.g. Ubuntu 24.04)

```
$ sudo ./install_DarkFirmware_real.sh
Backing up copy of /lib/firmware/rtl_bt/rtl8761bu_fw.bin.zst to /lib/firmware/rtl_bt/rtl8761bu_fw.bin.zst.orig.
DarkMentor firmware installed as /lib/firmware/rtl_bt/rtl8761bu_fw.bin.zst.
System doesn't use uncompressed firmware, skipping uncompressed firmware installation.
```

**Example of what's shown on a a system using uncompressed firmware**: (e.g. Raspbian Trixie)

```
$ sudo ./install_DarkFirmware_real.sh
System doesn't use compressed firmware, skipping compressed firmware installation.
Backing up copy of /lib/firmware/rtl_bt/rtl8761bu_fw.bin to /lib/firmware/rtl_bt/rtl8761bu_fw.bin.orig.
Decompressing ./DarkFirmware_real_i.bin.zst to /lib/firmware/rtl_bt/rtl8761bu_fw.bin.
./DarkFirmware_real_i.bin.zst: 45004 bytes                                     
DarkMentor firmware decompressed and installed as /lib/firmware/rtl_bt/rtl8761bu_fw.bin.
```

Then you will need to either unplug and re-plug the adapter, or issue `usbreset` with the VID/PID of the USB BT device, as found in `lsusb` (e.g. `2550:8761`, `0BDA:A728`, `2357:0604`, etc.)

```
$ usbreset 2550:8761
Resetting Bluetooth Radio ... ok
```

You should now see the BDADDR 13:37:13:37:13:37 in the output of `hciconfig`.

```
user@BTVM:~$ hciconfig 
hci0:	Type: Primary  Bus: USB
	BD Address: 13:37:13:37:13:37  ACL MTU: 1021:6  SCO MTU: 255:12
	UP RUNNING 
	RX bytes:1686 acl:0 sco:0 events:185 errors:0
	TX bytes:33933 acl:0 sco:0 commands:186 errors:0
```

You can now use the tools in the 04_XENO_VSC_RX_TX folder in this repository.

---
Copyright 2025 Dark Mentor LLC - [https://darkmentor.com](https://darkmentor.com)