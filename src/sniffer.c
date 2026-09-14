#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "../include/provo.h"

typedef struct {
    const provo_opts_t *opts;
    provo_stats_t *stats;
} callback_ctx_t;

static void packet_callback(unsigned char *user, const struct pcap_pkthdr *hdr,
                             const unsigned char *packet) {
    callback_ctx_t *ctx = (callback_ctx_t *)user;
    parser_handle_packet(packet, hdr->caplen, ctx->opts, ctx->stats);
}

/* Abre la interfaz, arranca el loop de captura. Devuelve el pcap_t para
 * que main.c lo pueda cerrar desde el manejador de Ctrl+C. */
pcap_t *sniffer_start(const provo_opts_t *opts, provo_stats_t *stats) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(opts->iface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, COL_YELLOW "Error abriendo interfaz '%s': %s" COL_RESET "\n",
                opts->iface, errbuf);
        fprintf(stderr, "Tip: corré PROVO con sudo, y verificá el nombre de "
                        "interfaz con 'ip link'.\n");
        return NULL;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, COL_YELLOW
                "Advertencia: la interfaz no es Ethernet estándar, "
                "el parseo puede fallar." COL_RESET "\n");
    }

    static callback_ctx_t ctx;
    ctx.opts = opts;
    ctx.stats = stats;

    printf(COL_BOLD COL_CYAN "PROVO" COL_RESET
           " escuchando en " COL_BOLD "%s" COL_RESET
           " (Ctrl+C para cortar y ver el resumen)\n\n", opts->iface);

    /* pcap_loop bloquea hasta pcap_breakloop() o error; -1 = sin límite de paquetes */
    pcap_loop(handle, -1, packet_callback, (unsigned char *)&ctx);

    return handle;
}
