import pyshark
import os

# 读取 PCAP 文件
# display_filter = '(tcp.port == 23) || (udp.port == 10000)'
display_filter = 'tcp || someip'
tshark_path = r"D:\Program Files\Wireshark\tshark.exe"

def extract_sequence(pcap_file):
    reference_cap = pyshark.FileCapture(pcap_file, display_filter=display_filter, tshark_path=tshark_path)
    reference_sequence = []

    for packet in reference_cap:
        if packet.highest_layer == 'SOMEIP':
            print("Someip")
        elif packet.highest_layer == 'TCP':
            print("tcp")

        # 可以继续添加其他类型的包，比如TCP数据传输、FIN等
    reference_cap.close()
    return reference_sequence


extract_sequence('TC8TestResult/TCP_CHECKSUM_01.pcap')