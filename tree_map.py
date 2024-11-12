import zipfile
import os

# Print file tree
def print_file_tree(file_path):
    print(f"\nFile Tree for: {file_path}\n")
    with zipfile.ZipFile(file_path, 'r') as zip_file:
        file_tree = {}
        for info in zip_file.infolist():
            parts = [part for part in info.filename.split('/') if part]
            current_level = file_tree
            for part in parts:
                if part not in current_level:
                    current_level[part] = {}
                current_level = current_level[part]

        def print_tree(level, indent=""):
            for key, value in level.items():
                if value:
                    print(f"{indent}|___{key}:")
                    print_tree(value, indent + "    ")
                else:
                    print(f"{indent}|___{key}")

        print(f"{os.path.basename(file_path)}:")
        print_tree(file_tree)
