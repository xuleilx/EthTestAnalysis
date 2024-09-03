from scapy.all import *

def modify_pcap(input_file, output_file, old_ip, new_ip, old_port, new_port):
    packets = rdpcap(input_file)
    for packet in packets:
        # 修改源IP和端口
        if IP in packet and packet[IP].src == old_ip:
            packet[IP].src = new_ip
        # if TCP in packet and packet[TCP].sport == old_port:
        if TCP in packet:
            packet[TCP].sport = new_port

        # 修改目的IP和端口
        if IP in packet and packet[IP].dst == old_ip:
            packet[IP].dst = new_ip
        # if TCP in packet and packet[TCP].dport == old_port:
        if TCP in packet:
            packet[TCP].dport = new_port

    # 保存修改后的PCAP文件
    wrpcap(output_file, packets)

input_file=r"D:\tmp\TCP_UNACCEPTABLE_13_CASE2.pcap"
output_file=r"D:\tmp\TCP_UNACCEPTABLE_13_CASE222.pcap"
# 使用示例
modify_pcap(input_file, output_file, '192.168.10.15', '192.168.10.16', 123, 23)
