CC=gcc
CFLAGS=-Wall
LIBS=-levent -lplist -lssl -lcrypto
ED25519_SRC=ed25519/ed25519.c ed25519/fe.c ed25519/sha512.c ed25519/ge.c ed25519/sc.c

all:
	$(CC) $(CFLAGS) example.c verification.c csrp/srp.c evrtsp/rtsp.c $(ED25519_SRC) -o example $(LIBS)
