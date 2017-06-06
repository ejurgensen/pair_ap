CC=gcc
CFLAGS=-Wall
LIBS=-levent -lplist -lssl -lcrypto -lsodium

all:
	$(CC) $(CFLAGS) example.c verification.c csrp/srp.c evrtsp/rtsp.c -o example $(LIBS)
