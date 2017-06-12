CC=gcc
#CFLAGS=-Wall -DCONFIG_OPENSSL
#LIBS=-levent -lplist -lssl -lcrypto -lsodium
CFLAGS=-Wall -DCONFIG_GCRYPT
LIBS=-levent -lplist -lgcrypt -lsodium

all:
	$(CC) $(CFLAGS) example.c verification.c evrtsp/rtsp.c -o example $(LIBS)
