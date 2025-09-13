#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <time.h>

#include "common.h"
#include "event_parser.skel.h"

static volatile sig_atomic_t exiting = 0;
static FILE *perf_file = NULL;
static FILE *flow_file = NULL;

static void handle_signal(int sig) {
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct flow_attribute *fa = data;
    if (!flow_file) return 0;

    fprintf(flow_file, "%lld,%u,%u,%u,%u,%u,%llu,%u\n",
            (long long)time(NULL),
            fa->dst_port,
            fa->max_packet_length,
            fa->total_length,
            fa->min_packet_length,
            fa->header_length,
            (unsigned long long)fa->min_duration,
            fa->num_packet);
    fflush(flow_file);

    return 0;
}

static void write_perf_stats_csv(int map_fd) {
    if (!perf_file) return;

    __u32 key = 0;
    int ncpu = libbpf_num_possible_cpus();
    struct perf_stat values[ncpu];

    if (bpf_map_lookup_elem(map_fd, &key, values) != 0) return;

    struct perf_stat agg = {};
    for (int i = 0; i < ncpu; i++) {
        agg.total_ns += values[i].total_ns;
        agg.calls += values[i].calls;
        if (values[i].max_ns > agg.max_ns)
            agg.max_ns = values[i].max_ns;
    }

    double avg_ns = (agg.calls > 0) ? (double)agg.total_ns / agg.calls : 0.0;
    fprintf(perf_file, "%lld,%.2f,%llu,%llu\n",
            (long long)time(NULL),
            avg_ns,
            agg.max_ns,
            agg.calls);
    fflush(perf_file);
}

int main(int argc, char **argv) {
    struct event_parser_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int ifindex, err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // 打开 CSV 文件
    perf_file = fopen("perf_stats.csv", "w");
    fprintf(perf_file, "timestamp,avg_ns,max_ns,calls\n");

    flow_file = fopen("flow_features.csv", "w");
    fprintf(flow_file, "timestamp,dst_port,max_pkt_len,total_len,min_pkt_len,header_len,min_iat,num_pkt\n");

    skel = event_parser_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "Failed to load BPF skeleton\n"); return 1; }

    const char *ifname = (argc > 1) ? argv[1] : "ens33";
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { perror("if_nametoindex"); goto cleanup; }

    link = bpf_program__attach_xdp(skel->progs.event_parser, ifindex);
    if (!link) { fprintf(stderr, "Failed to attach XDP\n"); goto cleanup; }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "Failed to create ring buffer\n"); goto cleanup; }

    int counter = 0;
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) break;

        if (++counter % 10 == 0) { // 每秒保存一次 perf_stats
            int map_fd = bpf_map__fd(skel->maps.perf_stats);
            write_perf_stats_csv(map_fd);
        }
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    if (link) bpf_link__destroy(link);
    if (skel) event_parser_bpf__destroy(skel);
    if (perf_file) fclose(perf_file);
    if (flow_file) fclose(flow_file);

    printf("Exiting program.\n");
    return 0;
}
