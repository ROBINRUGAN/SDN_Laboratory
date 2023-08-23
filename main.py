from scapy.all import *
from scapy.layers.inet import IP
import numpy as np
import random
import heapq

def random_sampling(data_stream, sample_size):
    # 使用随机采样从数据流中选择一部分数据包
    sampled_data = random.sample(data_stream, sample_size)
    return sampled_data

# count-min heap算法
class CountMinHeap:
    def __init__(self, num_hashes, num_buckets, k):
        # 初始化 Count-Min Sketch，指定哈希函数数量和桶的数量
        self.num_hashes = num_hashes
        self.num_buckets = num_buckets

        # 创建一个二维数组作为 Count-Min 表示，每行对应一个哈希函数
        self.sketch = np.zeros((num_hashes, num_buckets), dtype=np.int32)

        # 初始化 Count-Min Heap，指定 Top-k 的数量
        self.k = k
        # 创建一个最小堆来存储 Top-k 的频率估计和对应的元素
        self.min_heap = []

        # 创建一个集合用于存储已经添加到堆中的元素
        self.seen_elements = set()

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

    def add_with_heap(self, value):
        # 添加元素到 Count-Min Heap，并维护堆的大小
        freq_est = self.estimate_frequency(value)
        if len(self.min_heap) < self.k:
            if value not in self.seen_elements:
                heapq.heappush(self.min_heap, (freq_est, value))
                self.seen_elements.add(value)
        else:
            if freq_est > self.min_heap[0][0] and value not in self.seen_elements:
                removed = heapq.heappop(self.min_heap)[1]
                self.seen_elements.remove(removed)
                heapq.heappush(self.min_heap, (freq_est, value))
                self.seen_elements.add(value)

    def get_top_k(self):
        # 获取 Top-k 频率估计和对应的元素
        return self.min_heap


packets = rdpcap("trace2.pcap")

print(f"读取数据包已完成，一共有{len(packets)}条数据包")

num_select = 50000

print(f"我们对总体抽样{num_select}条数据包，意欲样本估计总体")

# 进行随机采样
selected_packets = random_sampling(list(packets), num_select)

# 哈希函数数量
num_hashes = 5

# 桶的数量
num_buckets = 10000

# top-k的k
k = 10

# 实例化
count_min_heap = CountMinHeap(num_hashes, num_buckets, k)

print("count-min sketch计算结束")

# count-min sketch频率计算处理
for packet in selected_packets:
    if packet.haslayer(IP):
        flow_key = (packet[IP].src, packet[IP].dst)
        count_min_heap.add(flow_key)

print("下面开始计算top-k，取k为10：")
# 维护堆，计算top-k
for packet in selected_packets:
    if packet.haslayer(IP):
        flow_key = (packet[IP].src, packet[IP].dst)
        count_min_heap.add_with_heap(flow_key)

top_k = count_min_heap.get_top_k()

top_k = sorted(top_k, key=lambda item: item[0], reverse=True)

# 打印结果及下标
for index, (freq, flow) in enumerate(top_k, start=1):
    print(f"第{index}大的抽样估计频率为：{freq} 源地址为：{flow[0]} 目标地址为：{flow[1]}")