#!/bin/bash
# By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com

# Check if the device address is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <Bluetooth Device Address>"
  exit 1
fi

# Get the Bluetooth device address from the command line argument
BDADDR="$1"

# Tokenize the Bluetooth address into the original endian order
BDADDR_ORIGINAL=$(echo "$BDADDR" | tr -d ':')
# Tokenize the Bluetooth address into the reversed endian order (flip byte order)
BDADDR_REVERSED=$(echo "$BDADDR" | tr ':' ' ' | awk '{for(i=NF;i>0;i--) printf "%s ", $i}')

# Generate the filename and xxd file path based on the original address order
FILENAME="my_config_${BDADDR_ORIGINAL}"
XXD_FILE="/tmp/${FILENAME}.xxd"
BIN_FILE="/tmp/${FILENAME}.bin"
ZST_FILE="/tmp/${FILENAME}.bin.zst"
BACKUP_FILE="/lib/firmware/rtl_bt/rtl8761bu_config.bin.zst.bak"
FINAL_FILE="/lib/firmware/rtl_bt/rtl8761bu_config.bin.zst"

# Construct the xxd command with the reversed byte order for the last 6 bytes
echo "00000000: 55 ab 23 87 09 00 30 00 06 ${BDADDR_REVERSED}" > "$XXD_FILE"

# Convert the xxd file back to a binary file
xxd -r "$XXD_FILE" > "$BIN_FILE"

# Compress the binary file using zstd
zstd "$BIN_FILE" -o "$ZST_FILE"

# Backup the original configuration file if it exists and the backup does not already exist
if [ -e "/lib/firmware/rtl_bt/rtl8761bu_config.bin.zst" ]; then
  if [ ! -e "$BACKUP_FILE" ]; then
    sudo cp /lib/firmware/rtl_bt/rtl8761bu_config.bin.zst "$BACKUP_FILE"
    echo "Backup created at $BACKUP_FILE."
  else
    echo "Backup already exists at $BACKUP_FILE. Skipping backup."
  fi
fi

# Copy the new zstd file to the firmware directory
sudo cp "$ZST_FILE" "$FINAL_FILE"

# Clean up temporary files
rm "$XXD_FILE" "$BIN_FILE" "$ZST_FILE"

echo "Firmware updated successfully with address $BDADDR."
