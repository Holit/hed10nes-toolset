import os
import sys
import hashlib

def calculate_md5(file_path):
    md5 = hashlib.md5()
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(8192)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()

def rename_files_with_md5(folder_path):
    files = os.listdir(folder_path)
    md5_counts = {}
    for file_name in files:
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            md5_hash = calculate_md5(file_path)
            md5_counts.setdefault(md5_hash, 0)
            md5_counts[md5_hash] += 1
            #new_file_name = f"{md5_hash}_{md5_counts[md5_hash]}" + os.path.splitext(file_name)[1]
            new_file_name = f"{md5_hash}"
            #防止重复
            if md5_counts[md5_hash] != 1:
                new_file_name = f"{md5_hash}_{md5_counts[md5_hash]}"
            new_file_path = os.path.join(folder_path, new_file_name)
            os.rename(file_path, new_file_path)
            print(f"Renamed {file_name} to {new_file_name}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python rename_as_md5.py <folder_path>")
        return

    folder_path = sys.argv[1]
    rename_files_with_md5(folder_path)
    print("File renaming completed.")

if __name__ == "__main__":
    main()
