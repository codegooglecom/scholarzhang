CC = cc
INCLUDES = -I.
LIBS = -L. -lpthread `pcap-config --libs` `libnet-config --libs` -lgfwkeyword
CFLAGS = -Wall -Wextra -g

all: url_keywords

url_keywords: url_keywords.c libgfwkeyword.a gfwkeyword.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

lib: libgfwkeyword.a

libgfwkeyword.a: gfwkeyword.o connmanager.o dstmaintain.o fingerprint.o
	ar rcs libgfwkeyword.a gfwkeyword.o connmanager.o dstmaintain.o fingerprint.o

gfwkeyword.o: gfwkeyword.c gfwkeyword.h connmanager.h dstmaintain.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

connmanager.o: connmanager.c connmanager.h dst_hash.c heap.h dstmaintain.h return_dst.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

dstmaintain.o: dstmaintain.c dstmaintain.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

fingerprint.o: fingerprint.c fingerprint.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm -f *.o libgfwkeyword.a url_keywords
