import binascii

import binascii

def view_zip_in_hex(file_path):
    print(f"\nViewing ZIP file in hex format: {file_path}\n")
    with open(file_path, 'rb') as f:
        content = f.read()
        hex_content = binascii.hexlify(content).decode('utf-8')
        for i in range(0, len(hex_content), 32):
            if i % 1024 == 0 and i != 0:
                sector_number = i // 1024
                print(f"-- Sector {sector_number} -- Assuming 512 Bytes ---")
            hex_line = hex_content[i:i+32]
            ascii_line = ''.join(chr(int(hex_line[j:j+2], 16)) if 32 <= int(hex_line[j:j+2], 16) <= 126 else '.' for j in range(0, len(hex_line), 2))
            print(f"[{i//2:08X}] {' '.join(hex_line[k:k+2].upper() for k in range(0, len(hex_line), 2))}  {ascii_line}")

def analyze_zip_hex(file_path):
    print(f"\nAnalyzing ZIP file in hex format: {file_path}\n")
    with open(file_path, 'rb') as f:
        hex_content = f.read().hex().upper()

    starting_tag = hex_content[0:8]
    version = hex_content[8:12]
    general_purpose_bit_flag = hex_content[12:16]
    compression_method = hex_content[16:20]
    file_last_mod_time = hex_content[20:24]
    file_last_mod_date = hex_content[24:28]
    crc = hex_content[28:36]
    compressed_size = hex_content[36:44]
    uncompressed_size = hex_content[44:52]
    file_name_length = hex_content[52:56]
    extra_field_length = hex_content[56:60]

    # Extracting the filename
    filename = bytes.fromhex(hex_content[60:60 + int(hex_content[52:54], 16) * 2]).decode('utf-8', errors='replace')

    print(f"Starting tag (should be 0x504b0304): {starting_tag}")
    print(f"Version: {version}")
    print(f"General purpose bit flag: {general_purpose_bit_flag}")
    print(f"Compression method: {compression_method}")
    print(f"File last modification time: {file_last_mod_time}")
    print(f"File last modification date: {file_last_mod_date}")
    print(f"CRC: {crc}")
    print(f"Compressed size: {compressed_size}")
    print(f"Uncompressed size: {uncompressed_size}")
    print(f"File name length: {file_name_length}")
    print(f"Extra field length: {extra_field_length}")
    print(f"Filename: {filename}")
