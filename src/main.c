#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include "../include/provo.h"

pcap_t *sniffer_start(const provo_opts_t *opts, provo_stats_t *stats);

static provo_stats_t g_stats;
static pcap_t *g_handle = NULL;

static void handle_sigint(int sig) {
    (void)sig;
    if (g_handle != NULL) {
        pcap_breakloop(g_handle);
    }
    stats_print_summary(&g_stats);
    exit(0);
}

static void print_usage(const char *prog) {
    printf("Uso: %s -i <interfaz> [-p tcp|udp|icmp] [--port <puerto>]\n\n", prog);
    printf("Ejemplos:\n");
    printf("  sudo %s -i eth0\n", prog);
    printf("  sudo %s -i wlan0 -p tcp\n", prog);
    printf("  sudo %s -i eth0 --port 443\n", prog);
}

int main(int argc, char *argv[]) {
    provo_opts_t opts;
    memset(&opts, 0, sizeof(opts));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            strncpy(opts.iface, argv[++i], sizeof(opts.iface) - 1);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            strncpy(opts.proto_filter, argv[++i], sizeof(opts.proto_filter) - 1);
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            opts.port_filter = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (opts.iface[0] == '\0') {
        fprintf(stderr, "Falta especificar interfaz.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    stats_init(&g_stats);
    signal(SIGINT, handle_sigint);

    g_handle = sniffer_start(&opts, &g_stats);
    if (g_handle == NULL) {
        return 1;
    }

    /* Si pcap_loop termina solo (sin Ctrl+C), igual mostramos el resumen */
    stats_print_summary(&g_stats);
    pcap_close(g_handle);
    return 0;
}
