#ifndef HANDLER_BPF_H
#define HANDLER_BPF_H

#include "vmlinux.h"
#include "common.h"

static inline void init_flow_attribute(struct flow_attribute *attr)
{
    attr->num_packet = 0;

    attr->min_packet_length = 0x7fffffffffffffffLL; // 设置为极大值，便于更新
    attr->max_packet_length = 0;

    attr->total_length = 0;

    attr->dst_port = 0;
    attr->header_length = 0;

    attr->min_duration = 0;

    attr->last_packet_time = 0;
    attr->status = 0;
    attr->total_feature_extraction_time = 0;
    attr->detection_start_time = 0;
}

// ✅ 每个数据包进入时，更新特征信息
static inline void update_flow_attribute(struct flow *f, struct tcphdr *tcp, u64 packet_length)
{
    u64 packet_time = bpf_ktime_get_ns(); // 当前时间
    u64 extraction_start_time = bpf_ktime_get_ns(); // 记录处理时间起点

    // 查找 flow 对应的属性记录
    struct flow_attribute *attr_ptr = (struct flow_attribute *)bpf_map_lookup_elem(&flow_map, f);

    // 如果没有记录，说明是第一次遇到这个流，进行初始化
    if (!attr_ptr)
    {
        struct flow_attribute attr = {};
        init_flow_attribute(&attr);

        attr.last_packet_time = packet_time;
        attr.dst_port = bpf_ntohs(tcp->dest); // 设置目的端口

        // 插入 flow 映射
        bpf_map_update_elem(&flow_map, f, &attr, BPF_NOEXIST);

        // 再次查找 pointer
        attr_ptr = (struct flow_attribute *)bpf_map_lookup_elem(&flow_map, f);
        if (!attr_ptr)
            return; // 安全检查失败
    }
    // ✅ 更新字段（训练 LightGBM 所需的6个特征）
    // 1. 包数量
    attr_ptr->num_packet += 1;

    // 2. Fwd Packet Length Min
    if (packet_length < attr_ptr->min_packet_length)
        attr_ptr->min_packet_length = packet_length;

    // 3. Fwd Packet Length Max
    if (packet_length > attr_ptr->max_packet_length)
        attr_ptr->max_packet_length = packet_length;

    // 4. Total Length of Fwd Packets
    attr_ptr->total_length += packet_length;

    // 5. Fwd IAT Min（包间最小时间间隔）
    if (attr_ptr->last_packet_time > 0)
    {
        u64 duration = packet_time - attr_ptr->last_packet_time;
        if (attr_ptr->min_duration == 0 || duration < attr_ptr->min_duration)
            attr_ptr->min_duration = duration;
    }
    attr_ptr->last_packet_time = packet_time;

    // 6. Fwd Header Length（以字节为单位）
    attr_ptr->header_length += tcp->doff * 4;

    // ✅ 特征提取耗时累计（可选性能指标）
    attr_ptr->total_feature_extraction_time += bpf_ktime_get_ns() - extraction_start_time;

    // ✅ 检测是否为流结束包（TCP FIN 或 RST）
    if (tcp->fin || tcp->rst)
    {
        attr_ptr->detection_start_time = bpf_ktime_get_ns(); // 标记流结束时间点
        // 此处后续你可以调用 perf_event_output 将特征发送到用户态
    }
}

#endif