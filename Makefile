CC=gcc
CFLAGS=-Wall
LIBS=-levent -lplist -lssl -lcrypto -lsodium

all:
	$(CC) $(CFLAGS) example.c verification.c evrtsp/rtsp.c -o example $(LIBS)
