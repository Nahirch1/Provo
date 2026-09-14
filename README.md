# PROVO

Analizador de tráfico de red en C puro, con captura en vivo, parseo manual
de cabeceras (Ethernet/IP/TCP/UDP/ICMP) y estadísticas en tiempo real
directamente en terminal.

## Por qué existe

Herramienta de portfolio pensada para mostrar manejo de C a bajo nivel:
sockets, punteros a estructuras de red, y lectura directa de bytes crudos
de paquetes — sin depender de librerías que abstraigan el parseo.

## Requisitos

- Linux
- gcc
- libpcap (`sudo apt install libpcap-dev` en Debian/Ubuntu)

## Compilación

```bash
make
```

## Uso

```bash
# Ver interfaces disponibles
ip link

# Capturar todo el tráfico de una interfaz (necesita permisos root)
sudo ./provo -i eth0

# Filtrar solo TCP
sudo ./provo -i eth0 -p tcp

# Filtrar por puerto (origen o destino)
sudo ./provo -i eth0 --port 443
```

Ctrl+C corta la captura y muestra un resumen: paquetes y bytes totales,
distribución por protocolo (con barras ASCII) y el top 5 de IPs con más
tráfico.

## Cómo está armado

- `src/sniffer.c` — apertura de interfaz y loop de captura con libpcap
- `src/parser.c` — parseo manual de cabeceras Ethernet, IP, TCP, UDP e ICMP
- `src/stats.c` — contadores por protocolo y ranking de IPs (top talkers)
- `src/main.c` — CLI, manejo de Ctrl+C y orquestación

## Próximos pasos posibles

- Soporte IPv6
- Exportar captura a PCAP para abrir en Wireshark
- Modo JSON de salida para integrarlo con otras herramientas
