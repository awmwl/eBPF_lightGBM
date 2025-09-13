#!/bin/bash
# 服务端启动脚本
# Usage: sudo ./run_xdp.sh <network_interface>
IFACE=${1:-ens33}

echo "Starting XDP program on $IFACE..."
sudo ./event_parser
XDP_PID=$!

echo "XDP PID: $XDP_PID"

# 等待 Python 采集程序启动
sleep 2

echo "XDP program is running. You can now start iperf3 client."
echo "Press Ctrl+C to stop."
wait $XDP_PID
