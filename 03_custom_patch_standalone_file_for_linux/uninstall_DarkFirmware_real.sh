#!/bin/bash
# By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com

FW_DIR="/lib/firmware/rtl_bt"
ORIG_ZST="$FW_DIR/rtl8761bu_fw.bin.zst.orig"
FW_ZST="$FW_DIR/rtl8761bu_fw.bin.zst"
ORIG_BIN="$FW_DIR/rtl8761bu_fw.bin.orig"
FW_BIN="$FW_DIR/rtl8761bu_fw.bin"
BACKUP_FW_D922="./rtl8761bu_fw_original_0xD922.bin.zst"

# Restore .zst firmware if backup exists
if [ -f "$ORIG_ZST" ]; then
    mv "$ORIG_ZST" "$FW_ZST"
    echo "Restored $ORIG_ZST to $FW_ZST."
else
    if [ -f "$FW_ZST" ]; then
        cp "$BACKUP_FW_D922" "$FW_ZST"
        echo "Restored $BACKUP_FW_D922 to $FW_ZST."
    fi
fi

# Restore .bin firmware if backup exists
if [ -f "$ORIG_BIN" ]; then
    mv "$ORIG_BIN" "$FW_BIN"
    echo "Restored $ORIG_BIN to $FW_BIN."
else
    if [ -f "$FW_BIN" ]; then
        zstd -d "$BACKUP_FW_D922" -o "$FW_ZST"
        echo "Restored $BACKUP_FW_D922 to $FW_BIN."
    fi
fi
