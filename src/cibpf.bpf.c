#include <bits/types.h>
#include <features.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/byteorder/little_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

#define UNFILTERED_PORT 8080

struct ciboulette{
    char name[10];
    int version;
    int action;
    int lenght;
    char * command;
};

unsigned char lookup_packet(struct xdp_md *ctx){
    __u16 source_port = 0, dest_port = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end){                                               
       return 0;                                                                               
    }
                                                                                               
    if ((void *)(eth + 1) > data_end) {
        return 0;  
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return 0;  
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return 0;  
    }

    if (ip->protocol == IPPROTO_TCP) {

        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

        if ((void *)(tcp + 1) > data_end) {
            return 0;  
        }

        source_port = __constant_ntohs(tcp->source);
        dest_port = __constant_ntohs(tcp->dest);

        if(dest_port == UNFILTERED_PORT){
            struct ciboulette *packet = (struct ciboulette *)(tcp + 1);

            bpf_printk("RECV: %s", packet->name);
        }
    }
    return dest_port;
}

SEC("xdp")
int ping(struct xdp_md *ctx){
    int retn = lookup_packet(ctx);

    if (retn){
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
