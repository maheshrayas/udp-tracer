#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

struct network_event_data
{
    __u64 inum;
    __u32 saddr;
    __u16 sport;
    __u32 daddr;
    __u16 dport;
    __u16 kind; // Egress
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tracept_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u32);
} inode_num SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} ignore_ips SEC(".maps");



static __always_inline __u32 *get_user_space_inum_ptr(struct sock *sk, __u64 *key)
{
    __u32 inum = 0;
    __u32 *user_space_inum_ptr = NULL;

    BPF_CORE_READ_INTO(&inum, sk, __sk_common.skc_net.net, ns.inum);
    *key = (__u64)inum;
    user_space_inum_ptr = bpf_map_lookup_elem(&inode_num, key);

    return user_space_inum_ptr;
}

SEC("kprobe/udp_recvmsg")
int trace_udp_send(struct pt_regs *ctx)
{
    struct network_event_data event = {};
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 key = 0;
    __u32 *user_space_inum_ptr = get_user_space_inum_ptr(sk, &key);

    if (!user_space_inum_ptr)
        return 0;

    u16 lport, dport;

    event.inum = key;
    bpf_probe_read(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    if (event.daddr == bpf_htonl(0x7F000001) || event.daddr == bpf_htonl(0x00000000))
    {
        return 0;
    }

    // if the source or destination IP is in the ignore list, return
    if (bpf_map_lookup_elem(&ignore_ips, &event.saddr) || bpf_map_lookup_elem(&ignore_ips, &event.daddr))
    {
        return 0;
    }

    // Ignore if source and destination IP are the same
    if (event.saddr == event.daddr)
    {
        return 0;
    }

    bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    event.kind = 3;
    event.sport = lport;
    event.dport = bpf_ntohs(dport);
    bpf_perf_event_output(ctx, &tracept_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}



char _license[] SEC("license") = "GPL";
