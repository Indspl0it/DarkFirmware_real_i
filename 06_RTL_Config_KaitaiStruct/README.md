# What are these?

* `rtl_config.ksy` - This is a [KaitaiStruct](https://kaitai.io/) definition (in its domain-specific language) of the structure of Realtek configuration files. The structure is a basic header followed by a TLV (Type-Length-Value) array. However, the structure itself is not that interesting. It is only useful if one knows what the specific "offset" values correspond to in terms of what value it's setting, as well as what the data means in the context of that value. However, the output of the parser can be used in conjunction with any public, private, or leaked Realtek documentation to understand what a config file is setting.

* `pyrtl_config` - Folder containing `rtl_config.py` which is created by the below KaitaiStruct Compiler (`ksc`) command. This should normally be generated dynamically with the below instructions. However, it was included to guarantee the `parse_rtl_config.py` code could work even on systems where KaitaiStruct wasn't installed.

* `parse_rtl_config.py` - Code which uses the python-based parsing library created by the KaitaiStruct compiler, to parse input Realtek config files.

# Usage

## Install prerequisite software

Only tested on Ubuntu 24.04.

```
cd ~/Downloads/
curl -LO https://github.com/kaitai-io/kaitai_struct_compiler/releases/download/0.10/kaitai-struct-compiler_0.10_all.deb
sudo apt install ./kaitai-struct-compiler_0.10_all.deb
sudo apt install python3-kaitaistruct
```

## Compile KaitaiStruct definition to create a Python parsing library

```
cd ~/darkfirmware_real_i/05_RTL_Config_KaitaiStruct/
ksc -t python --outdir pyrtl_config rtl_config.ksy
```

This creates `./pyrtl_config/rtl_config.py` which can be used by other code (`parse_rtl_config.py` in this case) to parse the config file.


## Parse specific config file

Decompress one of the example files:

```
zstd -d ../02_custom_patch_standalone_file_for_linux/rtl8761bu_config_001122334455.bin.zst -o ./rtl8761bu_config_001122334455.bin
```

Note its raw bytes with hexdump:

```
user@vm:~/darkfirmware_real_i/05_RTL_Config_KaitaiStruct$ hexdump -C rtl8761bu_config_001122334455.bin 
00000000  55 ab 23 87 09 00 30 00  06 55 44 33 22 11 00     |U.#...0..UD3"..|
0000000f
```

Now parse it to see a more semantically meaningful output:

```
user@vm:~/darkfirmware_real_i/05_RTL_Config_KaitaiStruct$ python3 ./parse_rtl_config.py --input ./rtl8761bu_config_001122334455.bin 
./rtl8761bu_config_001122334455.bin
Total len = 0x0009
offset (type) = 0x0030
  len_value = 0x06
  hex string value = 554433221100
```

So again, the tool doesn't tell you that offset 0x30 corresponds to setting a BDADDR on a RTL8761B\*-based dongle, or that the specific hex string is the little-endian encoding of the BDADDR. However, by consulting public, private, and leaked documentation you can use this to learn what some of the offsets and data types are, and then you can look around in the various config files found in `/lib/firmware/rtl_bt/` on Linux, or elsewhere for Android.

---
Copyright 2025 Dark Mentor LLC - [https://darkmentor.com](https://darkmentor.com)