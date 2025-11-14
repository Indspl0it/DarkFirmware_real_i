# What are these?

The **`RTL8761B_patch_modification.asm`** code is provided for study by other researchers and those who want to understand how the system modifies the RTL8761B patches. It is code written in MIPS16e assembly, which is notionally appended to an existing RTL8761B chip patch file and then invoked by insertion of an inline hook within the main patch file control flow.

The code creates a new Vendor Specific Command (VSC) (OCF = 0x222), which when sent to the now-patched chip, will turn around and use the bytes within that VSC as the packet payload for an LMP packet which can be sent to whichever device is the first (really 0th) device which the patched chip has an open connection to. The customized firmware then also sends back the packet payload for any LMP packets it receives via Vendor Specific Events (VSEs) (Event code = 0xFF). Software can therefore use VSCs to send custom LMP packets, and monitor VSEs to see the responses.

**`print_hex_bytes.py`** is a helper tool to export raw bytes appropriate for copying into `g_buf_poc` in [`RTL8761B_usbbluetooth_Patch_Writer.py`](../04_custom_patch_writer/RTL8761B_usbbluetooth_Patch_Writer.py).

**If you are not attempting to make changes yourself, you do not need to do anything with this code.**

# Making modifications

If you want to change the code's behavior, you must follow the below steps. They have only been tested on x86-64 and aarch64 Ubuntu 24.04.

## Learn MIPS16e assembly.

The "MIPS32® Architecture for Programmers Volume IV-a: The MIPS16e™ Application-Speciﬁc Extension to the MIPS32® Architecture" PDF is [mirrored](../doc_mirror/MD00076-2B-MIPS1632-AFP-02.63.pdf) in this repository. 

Note: When I started this work, I didn't actually know MIPS16e. But I knew RISC-V from teaching the ["Architecture 1005: RISC-V Assembly"](https://ost2.fyi/Arch1005) class at OpenSecurityTraining2. If you want to take the long (but deeper understanding) approach, you can learn RISC-V so you get a general understanding of the sorts of load/store/branch type mnemonics that are used here. If you come back after completed the Arch1005 class, reading the fun MIPS16e manual will be pretty trivial, compared to if you try to read it without familiarity with MIPS or related architectures. (Note: we will also have classes on MIPS asm at OST2 in the future.)

## Install prerequisites for compilation

You will need the GCC MIPS cross-compiler & binutils (for disassembly). On Ubuntu 24.04 this can be installed with the following command:

```
sudo apt install gcc-mips-linux-gnu binutils-mipsel-linux-gnu
```

## Modify code

E.g. as a test, add in a single `nop` instruction somewhere in `RTL8761B_patch_modification.asm`

## Compile code

```
mipsel-linux-gnu-as -mips32r2 -mips16 -o RTL8761B_patch_modification.o RTL8761B_patch_modification.asm
```

## Eyeball👁️ the disassembled code

Because debugging is so onerous, it is recommended that when you make any changes to the code, you read the output disassembled code first, to double check that what you think you changed, is what actually shows up.

```
mipsel-linux-gnu-objdump -mips16 -EL -d RTL8761B_patch_modification.o
```

The number 1 thing to be cautious about, is that PC-relative memory accesses to data stored in labels, need to be stored in 4-byte-aligned addresses (per the limitations of the encoding as given in the MIPS16e spec). I.e. if you want to write `lw $v0, my_label`, you need to make sure both the `my_label` and `lw` instr
uction itself are stored at an address which is a multiple of 4. This can be achieved with the application of the `.align 2` directive. That will insert a 2-byte no-op instruction as necessary, to ensure the instruction that follows it is on a 4-byte aligned address.

## Dump & copy raw bytes

You must then export the raw bytes of the assembled code, in a format appropriate for use elsewhere.

```
python3 ./print_hex_bytes.py

```

Take the first line of output (e.g. `0x5b,0xb3,0x80,0x9b,0x5c,0xb2,...`) and copy it into the array `g_poc_buf` in [`RTL8761B_usbbluetooth_Patch_Writer.py`](../04_custom_patch_writer/RTL8761B_usbbluetooth_Patch_Writer.py).

---
Copyright 2025 Dark Mentor LLC - [https://darkmentor.com](https://darkmentor.com)