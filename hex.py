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

def big_edian_2B(little_endian_hex):
    big_endian_hex = little_endian_hex[6:8] + little_endian_hex[4:6] + little_endian_hex[2:4] + little_endian_hex[0:2]
    dec = int(big_endian_hex, 16) * 2
    return dec

def big_edian_4B(little_endian_hex):
    big_endian_hex = little_endian_hex[14:16] + little_endian_hex[12:14] + little_endian_hex[10:12] + little_endian_hex[8:10] + little_endian_hex[6:8] + little_endian_hex[4:6] + little_endian_hex[2:4] + little_endian_hex[0:2]
    dec = int(big_endian_hex, 16) * 2
    return dec

def find_next_tag(hex_content, index):
    while index < len(hex_content):
        starting_tag = hex_content[index:index + 8]
        if starting_tag == "504B0304" or starting_tag == "504B0102" or starting_tag == "504B0506":
            return index
        index += 1
    return -1

def dec_date(decimal_value):
    decimal_value //= 2
    day = decimal_value & 0x1F
    month = (decimal_value >> 5) & 0x0F
    year = (decimal_value >> 9) + 1980
    # print(f"{decimal_value} = {day} | {month} | {year}")
    return f"{day}/{month}/{year}"

def dec_time(decimal_value):
    decimal_value //= 2
    hours = decimal_value // 3600
    minutes = (decimal_value % 3600) // 60
    seconds = decimal_value % 60
    # print(f"{decimal_value} = {hours:02}:{minutes:02}:{seconds:02}")
    return f"{hours:02}:{minutes:02}:{seconds:02}"

def extrafield_infos(extra_field):
    ID = extra_field[0:4]
    size_of_extra_field = extra_field[4:8]
    if ID == "0A00":
        type = "NTFS"
        reserved = extra_field[8:16]
        tag_of_attribute = extra_field[16:20]
        size_of_attribute = extra_field[20:24]
        last_modified = extra_field[24:40]
        last_accessed = extra_field[40:56]
        created = extra_field[56:72]
    if ID == "5554":
        type = "Extended Timestamp"
        info_bits = extra_field[8:10]
        last_modified = extra_field[10:18]
        last_accessed = extra_field[18:26]
        change = extra_field[26:34]
    if ID == "7578":
        type = "Unix UID/GID"
        version = extra_field[8:10]
        size_of_UID_field = extra_field[10:12]
        size_of_UID_field_dec = int(size_of_UID_field, 16) * 2
        UID = extra_field[12:12 + size_of_UID_field_dec]
        size_of_GID_field = extra_field[12 + size_of_UID_field_dec:12 + size_of_UID_field_dec + 2]
        size_of_GID_field_dec = int(size_of_GID_field, 16) * 2
        GID = extra_field[12 + size_of_UID_field_dec + 2:12 + size_of_UID_field_dec + 2 + size_of_GID_field_dec]
    if ID == "5558":
        type = "Unix"
        last_accessed = extra_field[8:16]
        last_modified = extra_field[16:24]
        UID = extra_field[24:28]
        GID = extra_field[28:32]
    if ID == "7570":
        type = "Info-ZIP unicode path"
        version = extra_field[8:10]
        CRC32_file_name = extra_field[10:18]
        file_name = extra_field[18:]

def parse_zip_file(hex_content):
    index = 0
    while index < len(hex_content):
        starting_tag = hex_content[index:index + 8]
        # print(f"\nIndex: {index} = {starting_tag}")

        if starting_tag == "504B0304":
            #? Local File Header
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

        elif starting_tag == "504B0102":
            #? Central Directory File Header
            version_made = hex_content[index + 8:index + 12]
            version = hex_content[index + 12:index + 16]
            general_purpose_bit_flag = hex_content[index + 16:index + 20]
            compression_method = hex_content[index + 20:index + 24]
            file_last_mod_time = hex_content[index + 24:index + 28]
            file_last_mod_date = hex_content[index + 28:index + 32]
            crc = hex_content[index + 32:index + 40]
            compressed_size = hex_content[index + 40:index + 48]
            uncompressed_size = hex_content[index + 48:index + 56]
            file_name_length = hex_content[index + 56:index + 60]
            extra_field_length = hex_content[index + 60:index + 64]
            file_comment_length = hex_content[index + 64:index + 68]
            disk_number_start = hex_content[index + 68:index + 72]
            internal_file_attributes = hex_content[index + 72:index + 76]
            external_file_attributes = hex_content[index + 76:index + 84]
            relative_offset_local_header = hex_content[index + 84:index + 92]

        elif starting_tag == "504B0506":
            #? End of Central Directory
            print(f"\nStarting tag: {starting_tag} = End of Central Directory")
            number_of_this_disk = hex_content[index + 8:index + 12]
            disk_where_central_directory_starts = hex_content[index + 12:index + 16]
            number_of_central_directory_records_on_this_disk = hex_content[index + 16:index + 20]
            total_number_of_central_directory_records = hex_content[index + 20:index + 24]
            size_of_central_directory = hex_content[index + 24:index + 32]
            offset_of_start_of_central_directory = hex_content[index + 32:index + 40]
            zip_file_comment_length = hex_content[index + 40:index + 44]

        if starting_tag != "504B0506":
            file_name_length_dec = big_edian_2B(file_name_length)
            extra_field_length_dec = big_edian_2B(extra_field_length)
            if starting_tag == "504B0102":
                file_comment_length_dec = big_edian_2B(file_comment_length)
            compressed_size_dec = big_edian_4B(compressed_size)

            if starting_tag == "504B0304":
                file_name = hex_content[index + 60:index + 60 + file_name_length_dec]
                filename = bytes.fromhex(file_name).decode('utf-8', errors='replace')
                extra_field = hex_content[index + 60 + file_name_length_dec:index + 60 + file_name_length_dec + extra_field_length_dec]
                # extrafield = bytes.fromhex(extra_field).decode('utf-8', errors='replace')

                if filename.endswith('/'):
                    print(f"\nStarting tag: {starting_tag} = Local Folder Header")
                else:
                    print(f"\nStarting tag: {starting_tag} = Local File Header")
            elif starting_tag == "504B0102":
                file_name = hex_content[index + 92:index + 92 + file_name_length_dec]
                filename = bytes.fromhex(file_name).decode('utf-8', errors='replace')
                extra_field = hex_content[index + 92 + file_name_length_dec:index + 92 + file_name_length_dec + extra_field_length_dec]
                # extrafield = bytes.fromhex(extra_field).decode('utf-8', errors='replace')
                file_comment = hex_content[index + 92 + file_name_length_dec + extra_field_length_dec:index + 92 + file_name_length_dec + extra_field_length_dec + file_comment_length_dec]
                filecomment = bytes.fromhex(file_comment).decode('utf-8', errors='replace')

                if filename.endswith('/'):
                    print(f"\nStarting tag: {starting_tag} = Central Directory Folder Header")
                else:
                    print(f"\nStarting tag: {starting_tag} = Central Directory File Header")

            if starting_tag == "504B0102":
                print(f"Version made by: {version_made} = {big_edian_2B(version)}")

            print(f"Version need to extract: {version} = {big_edian_2B(version)}")
            print(f"General purpose bit flag: {general_purpose_bit_flag} = {big_edian_2B(general_purpose_bit_flag)}")
            print(f"Compression method: {compression_method} = {big_edian_2B(compression_method)}")
            print(f"File last modification time: {file_last_mod_time} = {dec_time(big_edian_2B(file_last_mod_time))}")
            print(f"File last modification date: {file_last_mod_date} = {dec_date(big_edian_2B(file_last_mod_date))}")
            print(f"CRC-32: {crc} = {big_edian_4B(crc)}")
            print(f"Compressed size: {compressed_size} = {compressed_size_dec}")
            print(f"Uncompressed size: {uncompressed_size} = {big_edian_4B(uncompressed_size)}")
            print(f"File name length: {file_name_length} = {file_name_length_dec}")
            print(f"Extra field length: {extra_field_length} = {extra_field_length_dec}")

            if starting_tag == "504B0102":
                print(f"File comment length: {file_comment_length} = {big_edian_2B(file_comment_length)}")
                print(f"Disk number starts: {disk_number_start} = {big_edian_2B(disk_number_start)}")
                print(f"Internal file attributes: {internal_file_attributes} = {big_edian_2B(internal_file_attributes)}")
                print(f"External file attributes: {external_file_attributes} = {big_edian_4B(external_file_attributes)}")
                print(f"Relative offset of local header: {relative_offset_local_header} = {big_edian_4B(relative_offset_local_header)}")

            if filename.endswith('/'):
                print(f"Folder name: {file_name} = {filename}")
            else:
                print(f"File name: {file_name} = {filename}")
            if extra_field_length_dec > 0:
                print(f"Extra field: {extra_field}")
            if starting_tag == "504B0102" and file_comment_length_dec > 0:
                print(f"File comment: {file_comment} = {filecomment}")

            #! Move to the next file part
            if starting_tag == "504B0304": #? Local File Header
                file_data_start = index + 60 + file_name_length_dec + extra_field_length_dec
                # print(f"File data start: {file_data_start}")
                if compressed_size_dec > 0:
                    index = file_data_start + compressed_size_dec
                else:
                    index = find_next_tag(hex_content, file_data_start)
                    if index == -1:
                        break
            else: #? Central Directory File Header
                index = index + 92 + file_name_length_dec + extra_field_length_dec + file_comment_length_dec

        elif starting_tag == "504B0506":
            zip_file_comment_length_dec = big_edian_2B(zip_file_comment_length)

            zip_comment = hex_content[index + 44:index + 44 + zip_file_comment_length_dec]
            zipcomment = bytes.fromhex(zip_comment).decode('utf-8', errors='replace')

            print(f"Number of this disk: {number_of_this_disk} = {big_edian_2B(number_of_this_disk)}")
            print(f"Disk where central directory starts: {disk_where_central_directory_starts} = {big_edian_2B(disk_where_central_directory_starts)}")
            print(f"Number of central directory records on this disk: {number_of_central_directory_records_on_this_disk} = {big_edian_2B(number_of_central_directory_records_on_this_disk)}")
            print(f"Total number of central directory records: {total_number_of_central_directory_records} = {big_edian_2B(total_number_of_central_directory_records)}")
            print(f"Size of central directory: {size_of_central_directory} = {big_edian_4B(size_of_central_directory)}")
            print(f"Offset of start of central directory: {offset_of_start_of_central_directory} = {big_edian_4B(offset_of_start_of_central_directory)}")
            print(f"ZIP file comment length: {zip_file_comment_length} = {zip_file_comment_length_dec}")
            if zip_file_comment_length_dec > 0:
                print(f"ZIP file comment: {zip_comment} = {zipcomment}")

            #? Move to the end of the ZIP file
            index = index + 44 + zip_file_comment_length_dec

        else:
            print(f"\nStarting tag: {starting_tag} = Unknown")
            break

    print("\n-----End of ZIP file-----")

def analyze_zip_hex(file_path):
    print(f"\nAnalyzing ZIP file in hex format (little endian): {file_path}")
    with open(file_path, 'rb') as f:
        hex_content = f.read().hex().upper()
    parse_zip_file(hex_content)
