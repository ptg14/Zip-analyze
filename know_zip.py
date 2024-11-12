import argparse
from tree_map import print_file_tree
from analyze import analyze_zip_file

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze a ZIP file.')
    parser.add_argument('-f', '--file', type=str, required=True, help='Path to the ZIP file to analyze')
    parser.add_argument('-a', '--analyze', action='store_true', help='Analyze the ZIP file')
    parser.add_argument('-t', '--tree', action='store_true', help='Print the file tree of the ZIP file')
    parser.add_argument('-v', '--verbose', action="store_true", help="Enable verbose output.")
    args = parser.parse_args()

    if args.tree:
        print_file_tree(args.file)
    elif args.analyze:
        analyze_zip_file(args.file, verbose=args.verbose)
    else:
        print("Please provide either --analyze or --tree option.")
