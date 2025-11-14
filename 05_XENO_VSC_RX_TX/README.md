# What are these?

* **`bumble`** - Folder containing code from Google's [Bumble](https://github.com/google/bumble) project, at release v0.0.218, forked & customized to support sending the new VSC OCF 0x222 which allows sending arbitrary LMP packet contents.
* **`bumble/examples/run_classic_discoverable.py`** - Default example code to use Bumble to make a BT Classic device discoverable.
* **`bumble/examples/run_classic_discovery.py`** - Default example code to use Bumble to discover BT Classic discoverable devices.
* **`bumble/examples/Xeno_VSC_send_custom_LMP.py`** - Custom code to connect to a device and send it custom LMP packets via the "XENO VSC", and also log received LMP packets to BTIDES format, appropriate for importing to [Blue2thprinting](https://github.com/darkmentorllc/Blue2thprinting).

## Check out submodule

Since you most likely didn't follow the top-level README.md when it said to check out with `--recurse-submodules` (no one ever does ;)) you will need to fix up this repo by running the following command:

```
git submodule update --init --recursive
```

## Install prerequisite software

**Tested on**:  

 * Ubuntu 24.04 Linux VM on x86-64 & ARM  
 * Raspberry Pi 4b + Raspbian Bookworm x86-64 and Raspbian Trixie x86-32

**NOTE:** Bumble installation prerequisites (in particular `cryptography` and `grpcio`) compilation on a Raspberry Pi Zero W is ***incredibly*** slow (even if you up the swap space). For now, the Raspberry Pi Zero W should be considered unsupported.

About `uv`: `uv` is a Rust-based Python package manager, which handles things like creating virtual environments (venvs) and installing packages (like `pip`). The key benefit is that it's extremely much faster than `pip` for software installation, which matters a lot if you're going to use it on a low-power platform like a Raspberry Pi. However, because `uv` is not currently bundled with Debian-based distributions like Ubuntu 24.04 or Raspbian, you must use the `--break-system-packages` installation option as given below.

```
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libffi-dev libssl-dev rustc git
pip3 install uv --break-system-packages
echo "export PATH=$PATH:~/.local/bin/" >> ~/.bashrc
source ~/.bashrc
cd ~/rtl8761b_private/05_XENO_VSC_RX_TX
uv venv ./venvX
source ./venvX/bin/activate
uv pip install mysql.connector jsonschema colorama
cd bumble
uv tool install -e .
bumble-rtk-fw-download
```

The `uv tool install -e .` installs the local copy of Bumble with my changes to support sending the "XENO VSC" (Opcode Command Field (OCF) = 0x222), to the customized Realtek firmware, which is prepared to handle it.

### udev rules

On Linux you must create [udev rules](https://opensource.com/article/18/11/udev) for your specific USB device, so that you don't need to run the script as root.

Run `sudo nano /etc/udev/rules.d/99-usbbluetooth.rules`. Then add the following content (these being some of the common USB VID:PID (Vendor ID & Product ID) combos I see on my devices. Use `lsusb` to find if they match your device, and if not, add an entry for yours.)

```
SUBSYSTEM=="usb", ATTR{idVendor}=="2550", ATTR{idProduct}=="8761", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="0BDA", ATTR{idProduct}=="A728", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="0BDA", ATTR{idProduct}=="A729", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="2357", ATTR{idProduct}=="0604", MODE="0666"
```

Then save and exit, and run `sudo udevadm control --reload-rules && sudo udevadm trigger`.

### rfkill blocking

Your system may be set to block the addition of a USB BT dongle. E.g. in the below `hciconfig` output, the interface `hci1` is showing a status of "DOWN" after plugging in a dongle. This can be checked with `rfkill list all` and also unblocked, as shown. *If `rfkill list all` doesn't show anything, you can ignore this section.*

```
$ hciconfig
hci1:	Type: Primary  Bus: USB
	BD Address: A7:12:4C:41:53:F0  ACL MTU: 1021:6  SCO MTU: 255:12
	DOWN 
	RX bytes:1537 acl:0 sco:0 events:162 errors:0
	TX bytes:31106 acl:0 sco:0 commands:162 errors:0

hci0:	Type: Primary  Bus: UART
	BD Address: D9:76:86:82:21:F4  ACL MTU: 1021:8  SCO MTU: 64:1
	DOWN 
	RX bytes:3610 acl:0 sco:0 events:375 errors:0
	TX bytes:64639 acl:0 sco:0 commands:375 errors:0
$ rfkill list all
0: hci0: Bluetooth
	Soft blocked: yes
	Hard blocked: no
1: phy0: Wireless LAN
	Soft blocked: yes
	Hard blocked: no
2: hci1: Bluetooth
	Soft blocked: yes
	Hard blocked: no
$ sudo rfkill unblock 2
$ hciconfig -a hci1
hci1:	Type: Primary  Bus: USB
	BD Address: A7:12:4C:41:53:F0  ACL MTU: 1021:6  SCO MTU: 255:12
	UP RUNNING 
	RX bytes:2492 acl:0 sco:0 events:207 errors:0
	TX bytes:31781 acl:0 sco:0 commands:207 errors:0
	Features: 0xff 0xff 0xff 0xfe 0xdb 0xfd 0x7b 0x87
	Packet type: DM1 DM3 DM5 DH1 DH3 DH5 HV1 HV2 HV3 
	Link policy: RSWITCH HOLD SNIFF PARK 
	Link mode: PERIPHERAL ACCEPT 
	Name: 'pi4-2 #2'
	Class: 0x400000
	Service Classes: Telephony
	Device Class: Miscellaneous, 
	HCI Version: 5.1 (0xa)  Revision: 0xdfc6
	LMP Version: 5.1 (0xa)  Subversion: 0xd922
	Manufacturer: Realtek Semiconductor Corporation (93)
```

You want to see the "UP RUNNING" on your Realtek-based USB dongle before proceeding.

# Usage

## (Dongle & Terminal 1) Make a dongle discoverable via BT classic, so it can be connected to

The below command is not customized in any way, it's just the default Bumble command. It assumes that the dongle you want to apply it to is represented by USB:Vendor ID (VID):Product ID(PID) = `usb:2550:8761` (a common "EDUP" brand VID/PID). If your RTL8761B\*-based dongle has a different VID/PID, you will need to change the below. (Use `lsusb` to determine your device's VID/PID.)

```
cd examples
python3 ./run_classic_discoverable.py classic1.json usb:2550:8761
```

Note: if you want to change the name which the device broadcasts as, change the classic1.json contents.

## (Dongle & Terminal 2) Discover a discoverable BT classic device

*This is useful to sanity check the BDADDR for the device you want to connect to in the next step.* The below command is not customized in any way, it's just the default Bumble command. It assumes that the dongle you want to apply it to is represented by USB:Vendor ID (VID):Product ID(PID) = `usb:0bda:a728` (a common ["ZEXMTE"](https://amzn.to/4megB1x) VID/PID). If your RTL8761B\*-based dongle has a different VID/PID, you will need to change the below. (Use `lsusb` to determine your device's VID/PID.)

```
source ~/rtl8761b_private/05_XENO_VSC_RX_TX/venv/bin/activate
python3 ./run_classic_discovery.py usb:0bda:a728
```

You want to see a discoverable entry from Dongle 1 which looks like the following:

```
>>> 13:38:13:38:13:38/P:
  Device Class (raw): 240404
  Device Major Class: Audio/Video
  Device Minor Class: Wearable Headset Device
  Device Services: Rendering, Audio
  RSSI: -48
  [Complete Local Name]: "Bumble"
```

It's not really necessary for the target device to be running the full custom firmware; I'm just doing that here so it has a known hardcoded BDADDR. Otherwise you'd see a "Bumble" entry with the dongle's default-fused BDADDR, which you could use instead below.

## (Dongle & Terminal 2) Connect to a discoverable BT classic device

The below command is a customized version of the Bumble `run_classic_connect.py` command. The difference is that after it connects to a device, it sends custom LMP packets to that device, by sending a "XENO VSC", which subsequently have the buffer contents copied into an LMP packet by the custom firmware. The custom firmware sends it to the device which is the 0th in its array of connection structs. Which, if you haven't made any other connections since you restarted the dongle, should be the BDADDR given on the CLI (here, 13:38:13:38:13:38, implying the target is also running the custom Realtek firmware.) It assumes that the dongle you want to apply it to is represented by USB:Vendor ID (VID):Product ID(PID) = `usb:0bda:a728` (a common ["ZEXMTE"](https://amzn.to/4megB1x) VID/PID). If your RTL8761B\*-based dongle has a different VID/PID, you will need to change the below. (Use `lsusb` to determine your device's VID/PID.)

```
python3 ./Xeno_VSC_send_custom_LMP.py classic1.json usb:0bda:a728 13:38:13:38:13:38
```

If it succeeds, you should see data like the following towards the end of the output:

```
...
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
Remote name: Bumble
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
...
	LMP_FEATURES_RES seen
		Full packet data (without opcode): fffffffedbfd7b87
...
	LMP_VERSION_RES seen
		Full packet data (without opcode): 0a5d0022d9
...
Writing BTIDES data to file.
...
18:22:53.253 D bumble.host: ### DISCONNECTION: Connection(transport=0, peer_address=13:38:13:38:13:38/P), reason=22
18:22:53.253 D bumble.device: *** Disconnection: [0x0001] 13:38:13:38:13:38/P as CENTRAL, reason=22
18:22:53.253 D bumble.l2cap: disconnection from 1, cleaning up channels
=== Disconnected from 13:38:13:38:13:38/P
...
```

At the end you should also have a `LMP.btides` output file which conforms to the [BTIDES](https://github.com/darkmentorllc/BTIDES_Schema) format (and which can therefore be imported by [Blue2thprinting](https://github.com/darkmentorllc/Blue2thprinting)). You can view this is human-readable format with `python3 -m json.tool LMP.btides`, which could look something like this:

```
[
    {
        "bdaddr": "13:38:13:38:13:38",
        "bdaddr_rand": 0,
        "LMPArray": [
            {
                "opcode": 40,
                "full_pkt_hex_str": "fffffffedbfd7b87"
            },
            {
                "opcode": 39,
                "full_pkt_hex_str": "fffffffedbfd7b87"
            },
            {
                "opcode": 2,
                "full_pkt_hex_str": "000642756d626c650000000000000000"
            },
            {
                "opcode": 38,
                "full_pkt_hex_str": "0a5d0022d9"
            }
        ]
    }
]
```

So e.g. LMP opcode 38 = `LMP_VERSION_RES`, and therefore the `full_pkt_hex_str` would be interpreted as Version = 0x0A (BT spec v5.1), Company ID = 0x005D (Realtek), and Sub-version = 0xD922 (which we see actually came from the version (at offset 0x08) of the patch file downloaded!)

---
Copyright 2025 Dark Mentor LLC - [https://darkmentor.com](https://darkmentor.com)