import zipfile
import struct
import datetime

# Convert DOS date and time to datetime object
def dos_date_to_datetime(dos_date, dos_time):
    day = dos_date & 0x1F
    month = (dos_date >> 5) & 0x0F
    year = ((dos_date >> 9) & 0x7F) + 1980
    sec = (dos_time & 0x1F) * 2
    min = (dos_time >> 5) & 0x3F
    hour = (dos_time >> 11) & 0x1F
    return datetime.datetime(year, month, day, hour, min, sec)

# Read and parse Extra Fields
def read_extra_field(extra):
    index = 0
    fields = {}
    while index < len(extra):
        try:
            # Read Header ID (2 bytes) and Data Size (2 bytes)
            header_id, data_size = struct.unpack('<HH', extra[index:index+4])
            data = extra[index+4:index+4+data_size]

            # Handle specific IDs
            if header_id == 0x5455:  # Extended timestamps
                if len(data) >= 5:
                    info_bits = data[0]
                    # Extract `modified` time
                    fields['modified'] = datetime.datetime.fromtimestamp(struct.unpack('<I', data[1:5])[0])
                    # Extract `accessed` time if available and required by `info_bits`
                    if info_bits & 0x01 and len(data) >= 9:
                        fields['accessed'] = datetime.datetime.fromtimestamp(struct.unpack('<I', data[5:9])[0])
                    # Extract `created` time if available and required by `info_bits`
                    if info_bits & 0x02 and len(data) >= 13:
                        fields['created'] = datetime.datetime.fromtimestamp(struct.unpack('<I', data[9:13])[0])
            elif header_id == 0x7875:  # UNIX UID/GID
                if len(data) >= 4:
                    fields['uid'] = struct.unpack('<H', data[:2])[0]
                    fields['gid'] = struct.unpack('<H', data[2:4])[0]
            elif header_id == 0x7075:  # Language encoding flag (EFS)
                fields['unicode_path'] = data.decode('utf-8', errors='ignore')

            index += 4 + data_size
        except struct.error as e:
            print(f"Error unpacking data: {e}")
            break

    return fields

# Check for timestamp differences
def check_timestamp_difference(fields):
    if 'created' in fields and 'modified' in fields:
        delta = abs((fields['created'] - fields['modified']).total_seconds())
        if delta > 0:
            print(f"Possible timezone difference detected: {delta} seconds")

# Analyze ZIP file and detect the operating system that created it
def analyze_zip_file(file_path, verbose=False):
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_file:
            print("Analyzing ZIP file:", file_path)
            characteristics = {
                'NTFS_timestamp': False,
                'extended_timestamp': False,
                'unix_uid_gid': False,
                'unicode_path': False,
                'mac_folder': False
            }
            encoding = 'Unknown'

            for info in zip_file.infolist():
                if info.filename.endswith('/'):
                    if verbose:
                        print("\nFolder Name:", info.filename)
                else:
                    if verbose:
                        print("\nFile Name:", info.filename)
                        print("Compressed Size:", info.compress_size)
                        print("Uncompressed Size:", info.file_size)
                        print("Last Modified:", datetime.datetime(*info.date_time))

                # Read extra fields from file entry
                extra_fields = read_extra_field(info.extra)
                if verbose:
                    print("Extra Fields:", extra_fields)

                # Check for timestamp differences
                check_timestamp_difference(extra_fields)

                # Iterate over extra field header IDs
                idx = 0
                while idx < len(info.extra):
                    header_id, data_size = struct.unpack('<HH', info.extra[idx:idx+4])
                    if header_id == 0x000A:
                        characteristics['NTFS_timestamp'] = True
                    elif header_id == 0x5455:
                        characteristics['extended_timestamp'] = True
                    elif header_id == 0x5855:
                        characteristics['unix_uid_gid'] = True
                    elif header_id == 0x7075:
                        characteristics['unicode_path'] = True
                    idx += 4 + data_size

                # Determine encoding if possible
                if characteristics['unicode_path']:
                    encoding = 'UTF-8'
                elif characteristics['mac_folder']:
                    encoding = 'UTF-8'
                elif characteristics['NTFS_timestamp']:
                    encoding = 'UTF-16'
                else:
                    encoding = 'Unknown'

            # Identify probable source based on characteristics
            if characteristics['mac_folder']:
                origin = "macOS Compress or similar macOS tool"
            elif characteristics['NTFS_timestamp']:
                origin = "Windows-based tool"
            elif characteristics['extended_timestamp'] and characteristics['unix_uid_gid']:
                origin = "Unix/Linux tool, possibly on macOS or Ubuntu"
            elif characteristics['unicode_path']:
                origin = "Windows with Unicode support (e.g., WinRAR)"
            else:
                origin = "Unknown or unsupported tool"

            print("\n-----ZIP File Summary:")
            print(f"Probable ZIP file origin: {origin}")
            if verbose:
                print(f"Detected Characteristics: {characteristics}")
            print(f"Encoding used: {encoding}")
    except zipfile.BadZipFile:
        print("Error: The file is not a valid ZIP file.")
    except FileNotFoundError:
        print("Error: The file was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
