CC=gcc
CFLAGS=-Wall -DCONFIG_GCRYPT -DDEBUG_PAIR -g
LIBS=-levent -lplist-2.0 -lgcrypt -lsodium
#Possible alternatives:
#CFLAGS=-Wall -DCONFIG_OPENSSL -DDEBUG_PAIR -g
#LIBS=-levent -lplist -lssl -lcrypto -lsodium

all:
	$(CC) $(CFLAGS) client-example.c pair.c pair-tlv.c pair_fruit.c pair_homekit.c evrtsp/rtsp.c -o client-example $(LIBS)
	$(CC) $(CFLAGS) server-example.c pair.c pair-tlv.c pair_fruit.c pair_homekit.c -o server-example $(LIBS)
