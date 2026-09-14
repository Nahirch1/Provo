#include <stdio.h>
#include <string.h>
#include "../include/provo.h"

void stats_init(provo_stats_t *s) {
    memset(s, 0, sizeof(provo_stats_t));
}

void stats_register_protocol(provo_stats_t *s, int proto_code) {
    switch (proto_code) {
        case IPPROTO_TCP:  s->tcp_count++;  break;
        case IPPROTO_UDP:  s->udp_count++;  break;
        case IPPROTO_ICMP: s->icmp_count++; break;
        default:           s->other_count++; break;
    }
}

/* Busca la IP en la lista de talkers; si no está y hay lugar, la agrega */
void stats_register_talker(provo_stats_t *s, const char *ip, uint32_t bytes) {
    for (int i = 0; i < s->talker_count; i++) {
        if (strcmp(s->talkers[i].ip, ip) == 0) {
            s->talkers[i].packets++;
            s->talkers[i].bytes += bytes;
            return;
        }
    }
    if (s->talker_count < MAX_TALKERS) {
        talker_t *t = &s->talkers[s->talker_count++];
        strncpy(t->ip, ip, INET_ADDRSTRLEN - 1);
        t->packets = 1;
        t->bytes = bytes;
    }
}

/* Ordena por bytes descendente (selection sort, alcanza para MAX_TALKERS chico) */
static void sort_talkers_by_bytes(talker_t *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        int max_idx = i;
        for (int j = i + 1; j < n; j++) {
            if (arr[j].bytes > arr[max_idx].bytes) max_idx = j;
        }
        if (max_idx != i) {
            talker_t tmp = arr[i];
            arr[i] = arr[max_idx];
            arr[max_idx] = tmp;
        }
    }
}

/* Barra ASCII proporcional para el desglose por protocolo */
static void print_bar(const char *label, const char *color, uint64_t count, uint64_t total) {
    int width = 30;
    int filled = (total == 0) ? 0 : (int)((double)count / (double)total * width);
    printf("  %s%-6s%s [", color, label, COL_RESET);
    for (int i = 0; i < width; i++) putchar(i < filled ? '#' : ' ');
    printf("] %llu\n", (unsigned long long)count);
}

void stats_print_summary(const provo_stats_t *s) {
    printf("\n" COL_BOLD COL_CYAN "===== Resumen de captura - PROVO =====" COL_RESET "\n");
    printf("Paquetes totales: %s%llu%s\n", COL_BOLD,
           (unsigned long long)s->total_packets, COL_RESET);
    printf("Bytes totales:    %s%llu%s\n\n", COL_BOLD,
           (unsigned long long)s->total_bytes, COL_RESET);

    printf(COL_BOLD "Distribución por protocolo:" COL_RESET "\n");
    print_bar("TCP",   COL_GREEN,   s->tcp_count,   s->total_packets);
    print_bar("UDP",   COL_BLUE,    s->udp_count,   s->total_packets);
    print_bar("ICMP",  COL_YELLOW,  s->icmp_count,  s->total_packets);
    print_bar("Otros", COL_MAGENTA, s->other_count, s->total_packets);

    talker_t sorted[MAX_TALKERS];
    memcpy(sorted, s->talkers, sizeof(talker_t) * s->talker_count);
    sort_talkers_by_bytes(sorted, s->talker_count);

    printf("\n" COL_BOLD "Top IPs con más tráfico:" COL_RESET "\n");
    int top_n = s->talker_count < 5 ? s->talker_count : 5;
    for (int i = 0; i < top_n; i++) {
        printf("  %d. %-16s %8llu paquetes   %10llu bytes\n",
               i + 1, sorted[i].ip,
               (unsigned long long)sorted[i].packets,
               (unsigned long long)sorted[i].bytes);
    }
    printf(COL_BOLD COL_CYAN "=======================================" COL_RESET "\n");
}
