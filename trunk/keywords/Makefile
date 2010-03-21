CC = cc
INCLUDES = -I.
LIBS = -L. -lpthread `pcap_config --libs` `libnet-config --libs`
CFLAGS = -Wall -Wextra -g

all: url_keywords

url_keywords: url_keywords.c libgfwkeyword.a gfw_keyword.h
	$(CC) $(CFLAGS) -lgfwkeyword $(INCLUDES) -c $<

lib: libgfwkeyword.a

libgfwkeyword.a: gfw_keyword.o connmanager.o dstmaintain.o fingerprint.o
	ar rcs libufwutil.a gfw_keyword.o connmanager.o dstmaintain.o fingerprint.o

gfw_keyword.o: gfw_keyword.c gfw_keyword.h connmanager.h dstmaintain.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

connmanager.o: connmanager.c connmanager.h dst_hash.c heap.h dstmaintain.h return_dst.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

dstmaintain.o: dstmaintain.c dstmaintain.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

fingerprint.o: fingerprint.c fingerprint.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm -f *.o libgfwkeyword.a url_keywords
