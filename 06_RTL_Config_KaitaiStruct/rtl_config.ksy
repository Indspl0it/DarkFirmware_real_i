meta:
  id: rtl_config
  title: Realtek Config
  ks-version: 0.9
  endian: le
  bit-endian: le
  license: By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com
doc: |
  Config format used by Realtek to write values to memory/flash
seq:
  - id: header
    type: main_header
  - id: entries
    type: rtl_tlv
    repeat: eos
types:
  main_header:
    seq:
    - id: magic
      size: 4
      contents: [0x55, 0xab, 0x23, 0x87]
    - id: total_size
      type: u2
  rtl_tlv:
    seq:
      - id: offset
        type: u2
        doc: offset in flash?
      - id: len_value
        type: u1
      - id: value
        size: len_value
