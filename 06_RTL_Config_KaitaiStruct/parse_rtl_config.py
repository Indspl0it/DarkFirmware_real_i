# By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com

import argparse
from pyrtl_config.rtl_config import *

def main():
    parser = argparse.ArgumentParser(description='RTL Configuration file parser')
    io_group = parser.add_argument_group('Input/Output')
    io_group.add_argument('--input', type=str, required=True, help='Input file to parse.')

    args = parser.parse_args()
    print(args.input)

    data = RtlConfig.from_file(args.input)

    print(f"Total len = 0x{data.header.total_size:04x}")

    i1 = "  "
    for entry in data.entries:
        print(f"offset (type) = 0x{entry.offset:04x}")
        print(f"{i1}len_value = 0x{entry.len_value:02x}")
        hex_str_value = ''.join(format(byte, '02x') for byte in entry.value)
        print(f"{i1}hex string value = {hex_str_value}")

if __name__ == "__main__":
    main()

