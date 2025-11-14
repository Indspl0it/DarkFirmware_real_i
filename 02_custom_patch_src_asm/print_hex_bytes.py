# By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com
import sys

def main():
    # Hardcoded byte sequence to search for
    SEARCH_SEQUENCE = bytes([0x43, 0x43, 0x43, 0x43])

    filename = "RTL8761B_patch_modification.o"
    offset = 0x40
    buffer_size = 1024  # Read in chunks

    try:
        with open(filename, "rb") as f:
            f.seek(offset)
            accumulated_bytes = bytearray()
            
            while True:
                chunk = f.read(buffer_size)
                if not chunk:
                    break
                    
                accumulated_bytes.extend(chunk)
                if SEARCH_SEQUENCE in accumulated_bytes:
                    # Find where the sequence ends
                    end_idx = accumulated_bytes.find(SEARCH_SEQUENCE) + len(SEARCH_SEQUENCE)
                    # Only keep bytes up to end of sequence
                    accumulated_bytes = accumulated_bytes[:end_idx]
                    break

    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    # Convert to hex string representation
    hex_bytes = [f"0x{byte:02x}" for byte in accumulated_bytes]
    print(",".join(hex_bytes))
    print("")
    hex_bytes = [f"{byte:02x}" for byte in accumulated_bytes]
    print(" ".join(hex_bytes))


if __name__ == "__main__":
    main()
