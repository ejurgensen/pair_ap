CC=gcc
CFLAGS=-Wall
LIBS=-levent -lplist -lssl -lcrypto

all:
	$(CC) $(CFLAGS) pair.c csrp/srp.c evrtsp/rtsp.c -o pair $(LIBS)
