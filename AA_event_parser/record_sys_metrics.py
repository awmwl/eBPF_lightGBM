#!/usr/bin/env python3
import psutil
import time
import csv
from datetime import datetime

# 配置
OUTPUT_FILE = "system_metrics.csv"
INTERVAL = 1.0  # 秒，采样间隔
DURATION = 60   # 秒，总采样时间，可改为 None 无限循环

# 打开 CSV 文件并写入表头
with open(OUTPUT_FILE, mode='w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "cpu_sy_percent", "memory_used_MB"])

    start_time = time.time()
    while True:
        # 时间戳
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # CPU 信息（sy = system）
        cpu_times = psutil.cpu_times_percent(interval=None)
        cpu_sy = cpu_times.system  # 内核态百分比

        # 内存信息
        mem = psutil.virtual_memory()
        mem_used_mb = mem.used / 1024 / 1024

        # 写入 CSV
        writer.writerow([ts, cpu_sy, round(mem_used_mb, 2)])

        # 打印当前采样
        print(f"{ts} | CPU sy: {cpu_sy:.2f}% | Mem used: {mem_used_mb:.2f} MB")

        # 检查是否达到总时长
        if DURATION and (time.time() - start_time >= DURATION):
            break

        time.sleep(INTERVAL)
