// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#define ETH_P_IP 0x0800

char __license[] SEC("license") = "GPL";

// 最大 CPU 数，可通过 Makefile 覆盖
// #ifndef MAX_CPU
// #define MAX_CPU 128
// #endif

// 原始 flow 数据统计
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow);
    __type(value, struct flow_attribute);
} flow_map SEC(".maps");

// percpu array：每个 CPU 一份 perf_stat
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct perf_stat);
} perf_stats SEC(".maps");

// 向用户态输出已处理的六个特征
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB 缓冲，按需调整。不能太小，也别太大。
} events SEC(".maps");

/* ===================== 辅助函数 ===================== */


//XDP 中解析以太网 + IP + TCP header
static inline int flow_tuple(struct xdp_md *ctx, struct flow *f) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > (struct iphdr *)data_end)
        return -1;

    if (ip->protocol != IPPROTO_TCP)
        return -1;

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (tcp + 1 > (struct tcphdr *)data_end)
        return -1;

    f->saddr = ip->saddr;
    f->daddr = ip->daddr;
    f->sport = bpf_ntohs(tcp->source);
    f->dport = bpf_ntohs(tcp->dest);


    return 0;
}

static inline void init_flow_attribute(struct flow_attribute *attr)
{
    attr->num_packet = 0;
    attr->min_packet_length = (__u32)-1;
    attr->max_packet_length = 0;
    attr->total_length = 0;
    attr->dst_port = 0;
    attr->header_length = 0;
    attr->min_duration = (__u64)-1;
    attr->status = 0;
    attr->last_packet_time = 0;
    attr->total_feature_extraction_time = 0;
    attr->detection_start_time = 0;
}

// 更新 flow_attribute 特征
static inline void update_flow_attribute(struct xdp_md *ctx, struct flow *f, struct tcphdr *tcp, u32 packet_length) {
    u64 now = bpf_ktime_get_ns();
    u64 start_time = bpf_ktime_get_ns();
    u64 t0 = bpf_ktime_get_ns();


    // 查找 flow 对应的属性记录
    struct flow_attribute *attr = bpf_map_lookup_elem(&flow_map, f);


    // 如果没有记录，说明是第一次遇到这个流，进行初始化
    if (!attr) {
        struct flow_attribute init_attr = {};
        init_flow_attribute(&init_attr);


        init_attr.dst_port = tcp->dest;
        init_attr.last_packet_time = now;

        bpf_map_update_elem(&flow_map, f, &init_attr, BPF_NOEXIST);
        attr = bpf_map_lookup_elem(&flow_map, f);
        if (!attr) return;
    }

    // 1. 包数量
    attr->num_packet += 1;

    // 2. Fwd Packet Length Min
    if (packet_length < attr->min_packet_length)
        attr->min_packet_length = packet_length;

    // 3. Fwd Packet Length Max
    if (packet_length > attr->max_packet_length)
        attr->max_packet_length = packet_length;

    // 4. Total Length of Fwd Packets
    attr->total_length += packet_length;

    // 5. Fwd IAT Min（包间最小时间间隔）
    if (attr->last_packet_time !=0) {
        u64 duration = now - attr->last_packet_time;
        if (attr->min_duration == 0 || duration < attr->min_duration) {
            attr->min_duration = duration;
        }
    }
    attr->last_packet_time = now;

    // 6. Fwd Header Length（以字节为单位）
    attr->header_length += tcp->doff * 4;


   // 累积特征处理耗时
    attr->total_feature_extraction_time += bpf_ktime_get_ns() - start_time;

    // 如果流结束（TCP FIN / RST）发送到用户态
    if (tcp->fin || tcp->rst) {
        attr->detection_start_time = now;
        bpf_ringbuf_output(&events, attr, sizeof(*attr), 0);
        // 可选删除 flow_map 中记录
        // bpf_map_delete_elem(&flow_map, f);
    }

    u64 t1 = bpf_ktime_get_ns();
    u64 dur = 0;
    if (t1 >= t0)
        dur = t1 - t0;
    else
        dur = 0; // 理论上不会发生，但保险处理

    __u32 idx = 0;
    struct perf_stat *ps = bpf_map_lookup_elem(&perf_stats, &idx);
    if (ps) {
        ps->total_ns += dur;
        ps->calls += 1;
        if (dur > ps->max_ns)
            ps->max_ns = dur;
    }


}

/* ===================== XDP 主函数 ===================== */

SEC("xdp")
int event_parser(struct xdp_md *ctx) {
    struct flow f = {};
    if (flow_tuple(ctx, &f) < 0) return XDP_PASS;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void*)(tcp + 1) > data_end) return XDP_PASS;

    u32 packet_length = bpf_ntohs(ip->tot_len) - ip->ihl * 4;

    update_flow_attribute(ctx, &f, tcp, packet_length);

    return XDP_PASS;
}

