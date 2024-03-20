import os
import zlib

def calculate_crc(file_path):
    """
    计算文件的CRC值
    """
    crc_value = 0
    chunk_size = 8192  # 读取文件的块大小

    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            crc_value = zlib.crc32(chunk, crc_value)

    return crc_value

def main():
    current_directory = os.path.dirname(os.path.abspath(__file__))
    print(f"当前文件夹: {current_directory}")

    files_in_directory = [f for f in os.listdir(current_directory) if os.path.isfile(os.path.join(current_directory, f))]

    for file_name in files_in_directory:
        file_path = os.path.join(current_directory, file_name)
        crc_value = calculate_crc(file_path)
        print(f"{file_name}, 0x{crc_value:X}")

if __name__ == "__main__":
    main()
