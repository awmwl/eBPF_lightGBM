import time
import csv
import psutil
import signal
from ctypes import *

# ---------- 配置 ----------
PERF_STATS_MAP_FD = 3  # 通过 libbpf 获取 map fd
FLOW_CSV = "flow_features.csv"
PERF_CSV = "perf_stats.csv"

# ---------- 信号处理 ----------
exiting = False
def handle_sig(sig, frame):
    global exiting
    exiting = True
signal.signal(signal.SIGINT, handle_sig)
signal.signal(signal.SIGTERM, handle_sig)

# ---------- 内存与 CPU ----------
process = psutil.Process()  # 当前服务端采集脚本自身占用

# ---------- CSV ----------
perf_file = open(PERF_CSV, "w", newline="")
perf_writer = csv.writer(perf_file)
perf_writer.writerow(["timestamp", "total_ns", "max_ns", "calls", "rss_kb", "vms_kb", "cpu_percent"])

flow_file = open(FLOW_CSV, "w", newline="")
flow_writer = csv.writer(flow_file)
flow_writer.writerow([
    "timestamp", "Destination_Port", "Fwd_Packet_Length_Max", "Total_Length_of_Fwd_Packets",
    "Fwd_Packet_Length_Min", "Fwd_Header_Length", "Fwd_IAT_Min", "Num_Packets", "Last_Packet_Time"
])

# ---------- 模拟从 ring buffer 获取 flow (main.c 回调里可以写 CSV) ----------
def read_flow_events():
    # TODO: 从 ring buffer 或 perf ring 读取数据
    return []

# ---------- 主循环 ----------
print("Starting server-side collection... Ctrl+C to stop")
while not exiting:
    ts = time.time()

    # 1. perf stats
    total_ns, max_ns, calls = 0, 0, 0
    # TODO: 使用 libbpf map fd 读取 per-CPU perf_stats
    mem = process.memory_info()
    cpu = process.cpu_percent(interval=1)
    perf_writer.writerow([ts, total_ns, max_ns, calls, mem.rss//1024, mem.vms//1024, cpu])

    # 2. flow events
    flows = read_flow_events()
    for f in flows:
        flow_writer.writerow([
            ts,
            f["dst_port"], f["max_packet_length"], f["total_length"],
            f["min_packet_length"], f["header_length"], f["min_duration"],
            f["num_packet"], f["last_packet_time"]
        ])

perf_file.close()
flow_file.close()
print("Collection finished.")
