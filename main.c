#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>

#define bool int
#include <libnetfilter_queue/pktbuff.h>
#undef bool

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

enum src_or_dst {
    src,
    dst
} src_or_dst;
char *target_ip_address;

static int cb(
    struct nfq_q_handle *q,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *arg
) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    
    size_t packet_length;
    unsigned char   *packet_data;
    struct pkt_buff *packet;
    struct iphdr    *ip_header;
    struct tcphdr   *tcp_header;
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    
    packet_length = nfq_get_payload(nfa, &packet_data);
    packet = pktb_alloc(AF_INET, packet_data, packet_length, 4096);
    
    ip_header = nfq_ip_get_hdr(packet);
    nfq_ip_set_transport_header(packet, ip_header);
    tcp_header = nfq_tcp_get_hdr(packet);
    
    if (ip_header) {
        struct in_addr *target;
        if (src_or_dst == src) {
            target = (struct in_addr *) &ip_header->saddr;
        } else if (src_or_dst == dst) {
            target = (struct in_addr *) &ip_header->daddr;
        }
        inet_aton(target_ip_address, target);
        
        nfq_ip_set_checksum(ip_header);
        nfq_tcp_compute_checksum_ipv4(tcp_header, ip_header);
        memcpy(packet_data, pktb_data(packet), packet_length);
    }
    
    pktb_free(packet);
    
    return nfq_set_verdict(q, id, NF_ACCEPT, packet_length, packet_data);
}

void usage(char *cmd)
{
    fprintf(stderr, "Usage: %s <queue id> <src|dst> <target ip>\n", cmd);
}

int main(int argc, char *argv[])
{
    struct nfq_handle *h;
    struct nfq_q_handle *q;
    int rv, fd, queue_id;
    char buf[4096] __attribute__ ((aligned));
    
    src_or_dst = src;
    target_ip_address = "10.0.0.101";
    
    if (argc != 4) {
        usage(argv[0]);
        return -1;
    }
    
    queue_id = atoi(argv[1]);
    
    if (strcmp(argv[2], "src") == 0) {
        src_or_dst = src;
    } else if (strcmp(argv[2], "dst") == 0) {
        src_or_dst = dst;
    } else {
        usage(argv[0]);
        return -1;
    }
    
    if (inet_pton(AF_INET, argv[3], buf) != 1) {
        usage(argv[0]);
        return -1;
    }
    target_ip_address = argv[3];

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        return 1;
    }
    
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        return 1;
    }
    
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        return 1;
    }
    
    q = nfq_create_queue(h, queue_id, &cb, NULL);
    if (!q) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        return 1;
    }
    
    if (nfq_set_mode(q, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        return 1;
    }
    
    
    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }
    
    return 0;
}
