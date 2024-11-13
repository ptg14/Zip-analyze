import os
import sys
import datetime
import zipfile
import argparse
from tree_map import print_file_tree
from analyze import analyze_zip_file
from hex import view_zip_in_hex, analyze_zip_hex

def print_zip_info(file_path):
    print(f"ZIP File: {file_path}")
    print(f"  File Size: {os.path.getsize(file_path)} bytes")
    print(f"  Last Modified: {datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze a ZIP file.')
    parser.add_argument('-f', '--file', type=str, required=True, help='Path to the ZIP file to analyze')
    parser.add_argument('-o', '--output', type=str, help='Path to the output file')
    parser.add_argument('-a', '--analyze', action='store_true', help='Analyze the ZIP file')
    parser.add_argument('-t', '--tree', action='store_true', help='Print the file tree of the ZIP file')
    parser.add_argument('-x', '--hex', action='store_true', help='View the ZIP file in hex format (Can use with -a)')
    parser.add_argument('-v', '--verbose', action="store_true", help="Enable verbose output.")
    args = parser.parse_args()

    if args.output:
        sys.stdout = open(args.output, 'w')

    if not os.path.exists(args.file):
        print(f"Error: The file '{args.file}' does not exist.")
    elif not zipfile.is_zipfile(args.file):
        print(f"Error: The file '{args.file}' is not a valid ZIP file.")
    else:
        if args.analyze and args.hex:
            analyze_zip_hex(args.file)
        elif args.analyze:
            analyze_zip_file(args.file, verbose=args.verbose)
        elif args.tree:
            print_file_tree(args.file)
        elif args.hex:
            view_zip_in_hex(args.file)
        else:
            print_zip_info(args.file)

    if args.output:
        sys.stdout.close()
