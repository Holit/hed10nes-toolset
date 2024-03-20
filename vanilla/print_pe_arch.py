import os
import sys

def get_architecture(file_path):
    with open(file_path, 'rb') as file:
        # 读取前两个字节检查文件是否以'MZ'开头
        if file.read(2) == b'MZ':
            file.seek(60)  # 移动到PE头偏移位置
            pe_offset = int.from_bytes(file.read(4), 'little')  # 读取PE头偏移
            file.seek(pe_offset)  # 移动到PE头位置
            if file.read(4) == b'PE\x00\x00':  # 检查PE标志
                file.seek(pe_offset+4)  # 移动到PE文件头的Machine字段位置
                machine = int.from_bytes(file.read(2), 'little')  # 读取Machine字段
                if machine == 0x14C:
                    return "x86"
                elif machine == 0x8664:
                    return "x86-64"
                elif machine == 0x1C0:
                    return "ARM"
                else:
                    return f"0x{machine:02X}"
            else:
                return "Not a vaild PE file"
        else:
            return "Not a vaild COFF-PE file"
    return "Unknown"

def main(folder_path):
    files = os.listdir(folder_path)

    # 统计文件名长度
    max_file_name_length = max(len(file_name) for file_name in files)

    for file_name in files:
        file_path = os.path.join(folder_path, file_name)
        #if os.path.isfile(file_path) and file_name.endswith('.exe'):
        if os.path.isfile(file_path):
            architecture = get_architecture(file_path)
            print(f"{file_name.ljust(max_file_name_length)}: {architecture}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <folder_path>")
    else:
        folder_path = sys.argv[1]
        if not os.path.isdir(folder_path):
            print("Usage: python script.py <folder_path>")
        else:
            main(folder_path)
