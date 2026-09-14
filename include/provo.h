#ifndef PROVO_H
#define PROVO_H

#include <stdint.h>
#include <netinet/in.h>

#define MAX_TALKERS 64
#define MAX_FILTER_LEN 16

/* Colores ANSI */
#define COL_RESET   "\x1b[0m"
#define COL_GREEN   "\x1b[32m"   /* TCP */
#define COL_BLUE    "\x1b[34m"   /* UDP */
#define COL_YELLOW  "\x1b[33m"   /* ICMP */
#define COL_MAGENTA "\x1b[35m"   /* Otros */
#define COL_CYAN    "\x1b[36m"
#define COL_BOLD    "\x1b[1m"
#define COL_DIM     "\x1b[2m"

/* Un "talker" es una IP con contadores acumulados, para el ranking */
typedef struct {
    char ip[INET_ADDRSTRLEN];
    uint64_t packets;
    uint64_t bytes;
} talker_t;

/* Estadísticas globales de la sesión de captura */
typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t other_count;
    talker_t talkers[MAX_TALKERS];
    int talker_count;
} provo_stats_t;

/* Opciones de línea de comandos */
typedef struct {
    char iface[64];
    char proto_filter[MAX_FILTER_LEN]; /* "tcp", "udp", "icmp" o "" */
    int port_filter;                    /* 0 = sin filtro */
} provo_opts_t;

/* API de stats.c */
void stats_init(provo_stats_t *s);
void stats_register_protocol(provo_stats_t *s, int proto_code);
void stats_register_talker(provo_stats_t *s, const char *ip, uint32_t bytes);
void stats_print_summary(const provo_stats_t *s);

/* API de parser.c */
void parser_handle_packet(const unsigned char *packet, uint32_t caplen,
                           const provo_opts_t *opts, provo_stats_t *stats);

#endif
