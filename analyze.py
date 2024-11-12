import zipfile
import struct
import datetime

# Detect the operating system and app that created it
def detect_zip_origin(extra, file_list, zip_info_list, verbose=False):
    characteristics = {
        'Windows': 0,
        'MacOS': 0,
        'Ubuntu': 0,
        'WinRAR': 0,
        'WinZip': 0,
        '7-zip': 0,
        'Bandizip': 0,
        'Compress': 0,
        'zip': 0,
    }

    features = {
        'NTFS_timestamp': False,
        'nanoseconds_format': False,
        'extended_timestamp': False,
        'unix_uid_gid': False,
        'unicode_path': False,
        'root_folder_header': False,
        'double_zipping': False,
        'mac_folder': False,
        'data_descriptor': False,
    }

    idx = 0
    while idx < len(extra):
        try:
            header_id, data_size = struct.unpack('<HH', extra[idx:idx+4])
            data = extra[idx+4:idx+4+data_size]

            # Detect based on header_id
            if header_id == 0x000A:  # NTFS timestamp (Windows)
                characteristics['Windows'] += 2
                features['NTFS_timestamp'] = True
                if data.endswith(b'\xff\xff\xff\xff\xff\xff\xff\xff'):
                    features['nanoseconds_format'] = True
                    characteristics['Windows'] += 1

            elif header_id == 0x5455:  # Extended timestamps (Unix-based)
                characteristics['MacOS'] += 1
                characteristics['Ubuntu'] += 1
                features['extended_timestamp'] = True
                if data_size == 0x13:
                    characteristics['Compress'] += 2  # Specific to macOS Compress
                elif data_size == 0x09:
                    characteristics['zip'] += 2  # Common on Ubuntu

            elif header_id == 0x5855:  # Unix UID/GID (Linux/MacOS)
                characteristics['MacOS'] += 1
                characteristics['Ubuntu'] += 1
                features['unix_uid_gid'] = True

            elif header_id == 0x7075:  # Unicode path extra field (WinRAR)
                characteristics['WinRAR'] += 2
                characteristics['Windows'] += 1
                features['unicode_path'] = True

            elif header_id == 0x7875:  # UID and GID, common in Unix-based systems
                characteristics['Ubuntu'] += 1
                characteristics['MacOS'] += 1
                features['unix_uid_gid'] = True

            elif header_id == 0x50B4:  # WinZip specific header ID
                characteristics['WinZip'] += 2
                characteristics['Windows'] += 1

            idx += 4 + data_size

        except struct.error:
            print("Error reading extra field data")
            break

    for zip_info in zip_info_list:
        if zip_info.filename.startswith('__MACOSX'):
            features['mac_folder'] = True
            characteristics['MacOS'] += 3  # Strong indicator of macOS

        if zip_info.compress_type == zipfile.ZIP_STORED:
            features['double_zipping'] = True
            characteristics['7-zip'] += 1  # 7-zip is more likely to store ZIP files without recompression

        # Check for data descriptor (ZIP signature 0x08074b50 or 0x50 4B 07 08)
        if zip_info.extra and zip_info.extra[:4] == b'\x50\x4B\x07\x08':
            features['data_descriptor'] = True
            characteristics['Compress'] += 2  # Likely Compress on macOS

    root_folder = next((f for f in file_list if '/' in f and f.count('/') == 1), None)
    if root_folder:
        features['root_folder_header'] = True
        characteristics['Bandizip'] += 1  # Bandizip often includes root folder headers

    # Determine probable origin based on scores
    max_score = max(characteristics.values())
    likely_OS_apps = [key for key, value in characteristics.items() if value == max_score]

    if verbose:
        if len(likely_OS_apps) == 3:
            print("Unknown ZIP file origin")
        if len(likely_OS_apps) == 2:
            print(f"Likely ZIP file origins (tie): {', '.join(likely_OS_apps)}")
        else:
            print(f"Likely ZIP file origin: {likely_OS_apps[0]}")
        print(f"Scores by characteristics: {characteristics}")
        print(f"Detected Features: {features}")

    return characteristics

def print_extra_info(zip_info):
    # File comment (if any)
    if zip_info.comment:
        print(f"Comment: {zip_info.comment.decode('utf-8', 'ignore')}")
    else:
        print(f"Comment: None")

    # Read Extra Field for additional timestamps and IDs
    extra = zip_info.extra
    idx = 0
    created_date = modified_date = accessed_date = None
    uid = gid = None

    while idx < len(extra):
        header_id, data_size = struct.unpack('<HH', extra[idx:idx+4])
        data = extra[idx+4:idx+4+data_size]

        if header_id == 0x000A:  # NTFS timestamps (Windows)
            if data_size >= 24:
                mod_time, acc_time, cre_time = struct.unpack('<QQQ', data[:24])
                modified_date = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=mod_time // 10)
                accessed_date = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=acc_time // 10)
                created_date = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=cre_time // 10)
            print(f"Created Date (NTFS): {created_date}")
            print(f"Accessed Date (NTFS): {accessed_date}")
            print(f"Modified Date (NTFS): {modified_date}")

        elif header_id == 0x5455:  # Unix timestamps
            if data_size >= 5:
                info_bits = data[0]
                offset = 1
                if info_bits & 1:  # Modification time
                    mod_time_unix = struct.unpack('<I', data[offset:offset+4])[0]
                    modified_date = datetime.datetime.fromtimestamp(mod_time_unix)
                    offset += 4
                if info_bits & 2:  # Access time
                    acc_time_unix = struct.unpack('<I', data[offset:offset+4])[0]
                    accessed_date = datetime.datetime.fromtimestamp(acc_time_unix)
                    offset += 4
                if info_bits & 4:  # Creation time
                    cre_time_unix = struct.unpack('<I', data[offset:offset+4])[0]
                    created_date = datetime.datetime.fromtimestamp(cre_time_unix)
            print(f"Created Date (Unix): {created_date}")
            print(f"Accessed Date (Unix): {accessed_date}")
            print(f"Modified Date (Unix): {modified_date}")

        elif header_id == 0x7875:  # UNIX UID/GID
            if data_size >= 6:
                version, uid_size = struct.unpack('<BB', data[:2])
                uid = int.from_bytes(data[2:2 + uid_size], 'little')
                gid_size = data[2 + uid_size]
                gid = int.from_bytes(data[3 + uid_size:3 + uid_size + gid_size], 'little')
            print(f"UID: {uid}")
            print(f"GID: {gid}")

        idx += 4 + data_size

# Analyze ZIP file and detect the operating system that created it
def analyze_zip_file(file_path, verbose=False):
    with zipfile.ZipFile(file_path, 'r') as zip_file:
        print("\nAnalyzing ZIP file:", file_path)

        overall_characteristics = {
            'Windows': 0,
            'MacOS': 0,
            'Ubuntu': 0,
            'WinRAR': 0,
            'WinZip': 0,
            '7-zip': 0,
            'Bandizip': 0,
            'Compress': 0,
            'zip': 0,
        }

        for info in zip_file.infolist():
            if verbose:
                if info.filename.endswith('/'):
                    print("\nFolder Name:", info.filename)
                else:
                    print("\nFile Name:", info.filename)
                    print("Compressed Size:", info.compress_size)
                    print("Uncompressed Size:", info.file_size)
                    print("Last Modified:", datetime.datetime(*info.date_time))
                print_extra_info(info)
            characteristics = detect_zip_origin(info.extra, zip_file.namelist(), zip_file.infolist(), verbose)
            for key in overall_characteristics:
                overall_characteristics[key] += characteristics[key]

        #Final analysis
        max_score = max(overall_characteristics.values())
        likely_OS_apps = [key for key, value in overall_characteristics.items() if value == max_score]

        print("\n-----Final Analysis:-----")
        if len(likely_OS_apps) == 3:
            print("Unknown ZIP file origin")
        if len(likely_OS_apps) == 2:
            print(f"Likely ZIP file origins (tie): {', '.join(likely_OS_apps)}")
        else:
            print(f"Likely ZIP file origin: {likely_OS_apps[0]}")
        print(f"Scores by characteristics: {overall_characteristics}")
