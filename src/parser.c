#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "../include/provo.h"

static const char *proto_name(int proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "OTRO";
    }
}

static const char *proto_color(int proto) {
    switch (proto) {
        case IPPROTO_TCP:  return COL_GREEN;
        case IPPROTO_UDP:  return COL_BLUE;
        case IPPROTO_ICMP: return COL_YELLOW;
        default:           return COL_MAGENTA;
    }
}

/* Devuelve 1 si el paquete pasa el filtro pedido por línea de comandos */
static int passes_filter(const provo_opts_t *opts, int proto,
                          int src_port, int dst_port) {
    if (opts->proto_filter[0] != '\0') {
        const char *want = opts->proto_filter;
        if (strcmp(want, "tcp") == 0 && proto != IPPROTO_TCP) return 0;
        if (strcmp(want, "udp") == 0 && proto != IPPROTO_UDP) return 0;
        if (strcmp(want, "icmp") == 0 && proto != IPPROTO_ICMP) return 0;
    }
    if (opts->port_filter != 0) {
        if (src_port != opts->port_filter && dst_port != opts->port_filter) return 0;
    }
    return 1;
}

void parser_handle_packet(const unsigned char *packet, uint32_t caplen,
                           const provo_opts_t *opts, provo_stats_t *stats) {
    if (caplen < sizeof(struct ether_header)) return;

    const struct ether_header *eth = (const struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return; /* solo IPv4 por ahora */

    const unsigned char *ip_start = packet + sizeof(struct ether_header);
    if (caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;

    const struct ip *iph = (const struct ip *)ip_start;
    int ip_header_len = iph->ip_hl * 4;
    int proto = iph->ip_p;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &iph->ip_dst, dst_ip, sizeof(dst_ip));

    int src_port = 0, dst_port = 0;
    const unsigned char *l4_start = ip_start + ip_header_len;
    uint32_t remaining = caplen - sizeof(struct ether_header) - ip_header_len;

    if (proto == IPPROTO_TCP && remaining >= sizeof(struct tcphdr)) {
        const struct tcphdr *tcph = (const struct tcphdr *)l4_start;
        src_port = ntohs(tcph->source);
        dst_port = ntohs(tcph->dest);
    } else if (proto == IPPROTO_UDP && remaining >= sizeof(struct udphdr)) {
        const struct udphdr *udph = (const struct udphdr *)l4_start;
        src_port = ntohs(udph->source);
        dst_port = ntohs(udph->dest);
    }

    if (!passes_filter(opts, proto, src_port, dst_port)) return;

    uint32_t total_len = ntohs(iph->ip_len);

    /* Actualizar estadísticas */
    stats->total_packets++;
    stats->total_bytes += total_len;
    stats_register_protocol(stats, proto);
    stats_register_talker(stats, src_ip, total_len);

    /* Imprimir línea en vivo */
    printf("%s[%-4s]%s %-15s", proto_color(proto), proto_name(proto), COL_RESET, src_ip);
    if (src_port) printf(":%-5d", src_port); else printf("      ");
    printf(" -> %-15s", dst_ip);
    if (dst_port) printf(":%-5d", dst_port); else printf("      ");
    printf(COL_DIM " %5u bytes" COL_RESET "\n", total_len);
}
