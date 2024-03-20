import os
import sys

def read_first_bytes(file_path, num_bytes=16):
    with open(file_path, 'rb') as file:
        first_bytes = file.read(num_bytes)
    return first_bytes

def main(folder_path):
    files = os.listdir(folder_path)

    # 统计文件名长度
    max_file_name_length = max(len(file_name) for file_name in files)

    total_files = 0
    mz_files = 0

    for file_name in files:
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            total_files += 1
            first_bytes = read_first_bytes(file_path)
            first_bytes_hex = ' '.join(format(byte, '02X') for byte in first_bytes)
            mz_indicator = "'MZ'" if first_bytes[:2] == b'MZ' else ""
            print(f"{file_name.ljust(max_file_name_length)}: {first_bytes_hex} {mz_indicator}")
            if first_bytes[:2] == b'MZ':
                mz_files += 1
    
    mz_percentage = (mz_files / total_files) * 100 if total_files > 0 else 0
    print(f"\nTotal files: {total_files}")
    print(f"Files starting with 'MZ': {mz_files}")
    print(f"Percentage of files starting with 'MZ': {mz_percentage:.2f}%")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <folder_path>")
    else:
        folder_path = sys.argv[1]
        if not os.path.isdir(folder_path):
            print("not a folder: " + folder_path)
        else:
            main(folder_path)