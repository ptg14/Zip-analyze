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

def big_edian_4B(little_endian_hex):
    big_endian_hex = little_endian_hex[6:8] + little_endian_hex[4:6] + little_endian_hex[2:4] + little_endian_hex[0:2]
    dec = int(big_endian_hex, 16) * 2
    return dec

def big_edian_8B(little_endian_hex):
    big_endian_hex = little_endian_hex[14:16] + little_endian_hex[12:14] + little_endian_hex[10:12] + little_endian_hex[8:10] + little_endian_hex[6:8] + little_endian_hex[4:6] + little_endian_hex[2:4] + little_endian_hex[0:2]
    dec = int(big_endian_hex, 16) * 2
    return dec

def parse_zip_file(hex_content):
    index = 0
    while index < len(hex_content):
        starting_tag = hex_content[index:index + 8]
        print(f"Starting tag (should be 0x504b0304): {starting_tag}")
        if starting_tag == "504B0102":
            print("Central Directory File Header found")
            break

        version = hex_content[index + 8:index + 12]
        general_purpose_bit_flag = hex_content[index + 12:index + 16]
        compression_method = hex_content[index + 16:index + 20]
        file_last_mod_time = hex_content[index + 20:index + 24]
        file_last_mod_date = hex_content[index + 24:index + 28]
        crc = hex_content[index + 28:index + 36]
        compressed_size = hex_content[index + 36:index + 44]
        uncompressed_size = hex_content[index + 44:index + 52]
        file_name_length = hex_content[index + 52:index + 56]
        extra_field_length = hex_content[index + 56:index + 60]

        file_name_length_dec = big_edian_4B(file_name_length)
        file_name = hex_content[index + 60:index + 60 + file_name_length_dec]
        extra_field_length_dec = big_edian_4B(extra_field_length)
        compressed_size_dec = big_edian_8B(compressed_size)

        filename = bytes.fromhex(hex_content[index + 60:index + 60 + file_name_length_dec]).decode('utf-8', errors='replace')
        file_data_start = index + 60 + file_name_length_dec + extra_field_length_dec

        print(f"Version: {version} = {big_edian_4B(version)}")
        print(f"General purpose bit flag: {general_purpose_bit_flag} = {big_edian_4B(general_purpose_bit_flag)}")
        print(f"Compression method: {compression_method} = {big_edian_4B(compression_method)}")
        print(f"File last modification time: {file_last_mod_time} = {big_edian_4B(file_last_mod_time)}")
        print(f"File last modification date: {file_last_mod_date} = {big_edian_4B(file_last_mod_date)}")
        print(f"CRC: {crc} = {big_edian_8B(crc)}")
        print(f"Compressed size: {compressed_size} = {compressed_size_dec}")
        print(f"Uncompressed size: {uncompressed_size} = {big_edian_8B(uncompressed_size)}")
        print(f"File name length: {file_name_length} = {file_name_length_dec}")
        print(f"Extra field length: {extra_field_length} = {extra_field_length_dec}")
        print(f"Filename: {file_name} = {filename}\n")

        # Move to the next file header
        index = file_data_start + compressed_size_dec

def analyze_zip_hex(file_path):
    print(f"\nAnalyzing ZIP file in hex format (little endian): {file_path}\n")
    with open(file_path, 'rb') as f:
        hex_content = f.read().hex().upper()

    parse_zip_file(hex_content)
