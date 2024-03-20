import os
import sys

def print_directory_structure(folder_path, indent_level, max_depth):
    if indent_level > max_depth:
        return

    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isfile(item_path):
            print("|  " * (indent_level - 1) + "|--" + item)
        elif os.path.isdir(item_path):
            print("|  " * (indent_level - 1) + "|--" + item)
            print_directory_structure(item_path, indent_level + 1, max_depth)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python dtree.py <folder_path> <depth>")
        sys.exit(1)

    folder_path = sys.argv[1]
    depth = int(sys.argv[2])

    if not os.path.isdir(folder_path):
        print("Error: Specified folder does not exist.")
        sys.exit(1)

    print("Directory structure for", folder_path)
    print_directory_structure(folder_path, 1, depth)
