from scapy.all import *
from scapy.layers.inet import IP
import numpy as np

packets = rdpcap("trace2.pcap")
accuracy = {}

for packet in packets:
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if (src_ip, dst_ip) in accuracy:
            accuracy[(src_ip, dst_ip)] += 1
        else:
            accuracy[(src_ip, dst_ip)] = 1
"""
for ip, freq in accuracy.items():
    # 我们直接用频数当频率来看了
    print(f"源地址为{ip}的频率为{freq}")
"""


class CountMinSketch:
    def __init__(self, num_hashes, num_buckets):
        # 初始化 Count-Min Sketch，指定哈希函数数量和桶的数量
        self.num_hashes = num_hashes
        self.num_buckets = num_buckets
        # 创建一个二维数组作为 Count-Min 表示，每行对应一个哈希函数
        self.sketch = np.zeros((num_hashes, num_buckets), dtype=np.int32)

    def hash_functions(self, value):
        # 哈希函数，生成多个哈希值
        hash_values = []
        for i in range(self.num_hashes):
            # 通过将哈希函数的索引和值拼接，计算哈希值
            hash_value = hash(str(i) + str(value)) % self.num_buckets
            hash_values.append(hash_value)
        return hash_values

    def add(self, value):
        # 添加元素到 Count-Min Sketch
        hash_values = self.hash_functions(value)
        for i, hash_value in enumerate(hash_values):
            # 在相应的桶中增加计数
            self.sketch[i][hash_value] += 1

    def estimate_frequency(self, value):
        # 估计元素的频率
        hash_values = self.hash_functions(value)
        min_count = float('inf')
        for i, hash_value in enumerate(hash_values):
            # 找到多个哈希函数中最小的计数值
            min_count = min(min_count, self.sketch[i][hash_value])
        return min_count


num_hashes = 40
num_buckets = 10000
cms = CountMinSketch(num_hashes, num_buckets)

for packet in packets:
    if packet.haslayer(IP):
        flow_key = (packet[IP].src, packet[IP].dst)
        cms.add(flow_key)


sorted_accuracy = dict(sorted(accuracy.items(), key=lambda item: item[1], reverse=False))

for ip, freq in sorted_accuracy.items():
    estimate = cms.estimate_frequency(ip)
    print(f"源地址{ip} 的频率准确值为{freq}，频率估计值为{estimate}，相差值为{abs(freq - estimate)}")