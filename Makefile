CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap
SRC = src/main.c src/sniffer.c src/parser.c src/stats.c
BIN = provo

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
