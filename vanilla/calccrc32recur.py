import os
import hashlib

def calculate_hash(file_path):
    """
    计算文件的哈希值
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def process_directory(directory):
    """
    递归处理文件夹
    """
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(file_path, directory)
            file_hash = calculate_hash(file_path)
            print(f"{relative_path},{file_hash}")

def main():
    current_directory = os.path.dirname(os.path.abspath(__file__))
    print(f"path,hash")

    process_directory(current_directory)

if __name__ == "__main__":
    main()
