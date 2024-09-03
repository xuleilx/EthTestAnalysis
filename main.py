import pyshark
import os

# 读取 PCAP 文件
display_filter = r'(tcp.port == 23) || (udp.port == 10000)'
tshark_path = r"D:\Program Files\Wireshark\tshark.exe"

# 定义需要映射的 IP 地址和对应的映射值
IP_MAPPINGS = {
    # ref
    '192.168.10.15': 'DUT',
    '192.168.10.21': 'Tester',
    '192.168.10.3': 'LTester',
    # act
    '192.168.22.22': 'DUT',
    '192.168.22.84': 'Tester',
    '192.168.22.101': 'LTester'
}

def map_ip(ip):
    return IP_MAPPINGS.get(ip, ip)  # 如果 IP 在映射中，则返回映射值，否则返回原始 IP

def extract_sequence(pcap_file):
    reference_cap = pyshark.FileCapture(pcap_file, display_filter=display_filter, tshark_path=tshark_path)
    reference_sequence = []
    try:
        for packet in reference_cap:
            if 'SOMEIP' in packet:
                reference_sequence.append({
                    'type': 'SOMEIP',
                    'src_ip': map_ip(packet.ip.src),
                    'dst_ip': map_ip(packet.ip.dst),
                    'service_id': packet.someip.serviceid,
                    'method_id': packet.someip.methodid
                })
            elif 'TCP' in packet:
                tcp_header_length = int(packet.tcp.hdr_len)
                if tcp_header_length < 20:
                    # skip flags
                    tcp_flags = 0
                else:
                    tcp_flags = packet.tcp.flags
                reference_sequence.append({
                    'type': 'TCP',
                    'src_ip': map_ip(packet.ip.src),
                    'dst_ip': map_ip(packet.ip.dst),
                    'flags': tcp_flags
                })
    except Exception as e:
        print(f"exception：{e}")
    finally:
        reference_cap.close()

    return reference_sequence


def compare_sequences(reference_sequence, actual_sequence):
    correct_order = True
    sequence_length = min(len(reference_sequence), len(actual_sequence))

    for i in range(sequence_length):
        ref = reference_sequence[i]
        actual = actual_sequence[i]

        if ref['type'] != actual['type'] or ref['src_ip'] != actual['src_ip'] or ref['dst_ip'] != actual['dst_ip']:
            correct_order = False
            print(f"\033[31m[NG]\033[0m\n"
                  f"\tError at frame {i + 1}: \n"
                  f"\tExpected\t{ref}, \n"
                  f"\tActual  \t{actual}")
            break
        if ref['type'] == 'SOMEIP' and ref['method_id'] != actual['method_id']:
            correct_order = False
            print(f"\033[31m[NG]\033[0m\n"
                  f"\tError at frame {i + 1}: \n"
                  f"\tExpected\t{ref}, \n"
                  f"\tActual  \t{actual}")
            break
        if ref['type'] == 'TCP' and ref['flags'] != actual['flags']:
            correct_order = False
            print(f"\033[31m[NG]\033[0m\n"
                  f"\tError at frame {i + 1}: \n"
                  f"\tExpected\t{ref}, \n"
                  f"\tActual  \t{actual}")
            break

    if correct_order:
        if len(reference_sequence) == len(actual_sequence):
            print("\033[32m[OK]\033[0m")
        else:
            print("\033[31m[NG]\033[0m The lengths differ.")


def check_file_exists(file_path):
    if os.path.exists(file_path):
        print(f"File exists: {file_path}")
    else:
        print(f"File does not exist: {file_path}")


# 提取参考报文和实际报文中的序列
def scan_directory(reference_dir, actual_dir):
    # 遍历目录下的所有文件和子目录
    files_pair =[]
    for root, dirs, files in os.walk(actual_dir):
        for file in files:
            # 构建文件的完整路径
            reference_file = os.path.join(reference_dir, file)
            actual_file = os.path.join(actual_dir, file)
            if not os.path.exists(reference_file):
                files_pair.append({'ref': "", 'act': actual_file})
            else:
                files_pair.append({'ref': reference_file,'act': actual_file})
    return files_pair

if __name__ == "__main__":
    # 使用示例，指定要扫描的目录路径
    files_pair = scan_directory('TC8StandardPacket', 'TC8TestResult')
    #files_pair = scan_directory(r'E:\00_work\Ethernet\TestResult\TCP_2023-10-10_19-49-27', r'D:\tmp\test_result')
    for file in files_pair:
        print(f"{os.path.basename(file['act'])} ", end='')
        if file['ref'] == "":
            print(f"\033[31m[NG]\033[0m\n\t Standard packet not exist, should check by yourself.")
            continue
        reference_sequence = extract_sequence(file['ref'])
        actual_sequence = extract_sequence(file['act'])
        # 对比序列
        compare_sequences(reference_sequence, actual_sequence)
