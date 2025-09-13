#ifndef COMMON_H
#define COMMON_H

// Destination Port	432	14.00774
// Fwd Packet Length Max	232	12.78186
// Total Length of Fwd Packets	149	10.61462

// Fwd Packet Length Min	157	6.036202
// Fwd Header Length	331	5.716277
// Fwd IAT Min	220	5.106769

struct flow_attribute {
    __u32 dst_port;                  // 目标端口
    __u32 max_packet_length;         // 最大包长
    __u32 total_length;              // 转发包总长度
    __u32 min_packet_length;         // 最小包长
    __u32 header_length;             // TCP头部长度
    __u64 min_duration;              // 最小报文间隔
    __u32 num_packet;                // 报文数量
    __u32 status;                    // 状态标志
    __u64 last_packet_time;          // 上次报文时间戳
    __u64 total_feature_extraction_time; // 特征提取累计耗时
    __u64 detection_start_time;      // 检测开始时间
};


struct flow {
    __u32 saddr;   // 源 IPv4 地址
    __u32 daddr;   // 目的 IPv4 地址
    __u16 sport;   // 源端口
    __u16 dport;   // 目的端口
    __u32 pad;   // 对齐到 16 字节
    // __u8  proto;   // 协议号 (TCP=6, UDP=17)
};

// 定义 perf_stat 结构（放在 includes 之后、map 定义之前）
struct perf_stat {
    __u64 total_ns;   // 累计耗时（纳秒）
    __u64 max_ns;     // 单次最大耗时（纳秒）
    __u64 calls;      // 调用次数
};

#endif