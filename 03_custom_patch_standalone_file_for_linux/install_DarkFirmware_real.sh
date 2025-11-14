#!/bin/bash
# By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com

FW_DIR="/lib/firmware/rtl_bt"
FW_ZST="$FW_DIR/rtl8761bu_fw.bin.zst"
ORIG_ZST="$FW_DIR/rtl8761bu_fw.bin.zst.orig"
FW_BIN="$FW_DIR/rtl8761bu_fw.bin"
ORIG_BIN="$FW_DIR/rtl8761bu_fw.bin.orig"
DM_FW_ZST="./DarkFirmware_real_i.bin.zst"

if [ ! -f "$DM_FW_ZST" ]; then
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <path/to/DarkFirmware_real_i.bin.zst>"
        exit 1
    else
        DM_FW_ZST="$1"
    fi
fi

####################################################################################
# Handle case that system uses a compressed firmware
####################################################################################

# Backup .bin.zst if .zst.orig does not exist
if [ -f "$FW_ZST" ] && [ ! -f "$ORIG_ZST" ]; then
    echo "Backing up copy of $FW_ZST to $ORIG_ZST."
    cp "$FW_ZST" "$ORIG_ZST"
else
    if [ ! -f "$FW_ZST" ]; then
        echo "System doesn't use compressed firmware, skipping compressed firmware installation."
    fi
    if [ -f "$ORIG_ZST" ]; then
        echo "Original .zst firmware already backed up to $ORIG_ZST, skipping."
    fi
fi

# Sanity check: Only install DarkMentor firmware if it exists
if [ -f "$FW_ZST" ] && [ -f "$ORIG_ZST" ] && [ -f "$DM_FW_ZST" ]; then
    cp "$DM_FW_ZST" "$FW_ZST"
    echo "DarkMentor firmware installed as $FW_ZST."
else
    if [ ! -f "$DM_FW_ZST" ]; then
        echo "DarkMentor firmware file $DM_FW_ZST not found. Skipping installation."
    fi
fi

####################################################################################
# Handle case that system uses an uncompressed firmware
####################################################################################

# Backup .bin if .bin.orig does not exist
if [ -f "$FW_BIN" ] && [ ! -f "$ORIG_BIN" ]; then
    echo "Backing up copy of $FW_BIN to $ORIG_BIN."
    cp "$FW_BIN" "$ORIG_BIN"
else
    if [ ! -f "$FW_BIN" ]; then
        echo "System doesn't use uncompressed firmware, skipping uncompressed firmware installation."
    fi
    if [ -f "$ORIG_BIN" ]; then
        echo "Original uncompressed firmware already backed up to $ORIG_BIN, skipping."
    fi
fi

# If .bin.orig exists and DM_FW_ZST exists, decompress DarkMentor firmware to .bin
if [ -f "$FW_BIN" ] && [ -f "$ORIG_BIN" ] && [ -f "$DM_FW_ZST" ]; then
    echo "Decompressing $DM_FW_ZST to $FW_BIN."
    zstd -f -d "$DM_FW_ZST" -o "$FW_BIN"
    echo "DarkMentor firmware decompressed and installed as $FW_BIN."
else
    if [ ! -f "$DM_FW_ZST" ]; then
        echo "DarkMentor firmware file $DM_FW_ZST not found. Skipping installation."
    fi
fi
