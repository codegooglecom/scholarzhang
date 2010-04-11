CC = cc
INCLUDES = -I.
LIBS = -L. `pcap-config --libs` `libnet-config --libs` -lgfwkeyword
CFLAGS = -Wall -Wextra -g

all: url_keywords

url_keywords: url_keywords.c libgfwkeyword.a gfwkeyword.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS) -lpthread

lib: libgfwkeyword.a

libgfwkeyword.a: gfwkeyword.o connmanager.o dstmaintain.o fingerprint.o
	ar rcs $@ gfwkeyword.o connmanager.o dstmaintain.o fingerprint.o

gfwkeyword.o: gfwkeyword.c gfwkeyword.h connmanager.h dstmaintain.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

connmanager.o: connmanager.c connmanager.h dst_hash.c heap.h dstmaintain.h return_dst.c fingerprint.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

dstmaintain.o: dstmaintain.c dstmaintain.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

fingerprint.o: fingerprint.c fingerprint.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

fingerprint.c: fingerprint.loose.c
	ln -s $< $@

fingerprint.h: fingerprint.loose.h
	ln -s $< $@

clean:
	rm -f *.o libgfwkeyword.a url_keywords
