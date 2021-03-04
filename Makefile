CC=gcc
#CFLAGS=-Wall -DCONFIG_OPENSSL -DDEBUG_PAIR -g
#LIBS=-levent -lplist -lssl -lcrypto -lsodium
CFLAGS=-Wall -DCONFIG_GCRYPT  -DDEBUG_PAIR -g
LIBS=-levent -lplist -lgcrypt -lsodium

all:
	$(CC) $(CFLAGS) pair-example.c pair.c pair-tlv.c pair_fruit.c pair_homekit.c evrtsp/rtsp.c -o pair-example $(LIBS)
