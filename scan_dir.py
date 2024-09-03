import os

def scan_directory(directory):
    # 遍历目录下的所有文件和子目录
    for root, dirs, files in os.walk(directory):
        for file in files:
            # 构建文件的完整路径
            file_path = os.path.join(root, file)
            print(file_path)

# 使用示例，指定要扫描的目录路径
scan_directory('TC8StandardPacket')
