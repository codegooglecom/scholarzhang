CC = gcc
LIBS =	`pkg-config --libs glib-2.0` \
		`pkg-config --libs gthread-2.0` \
		`libnet-config --libs` \
		`pcap-config --libs`
INCLUDES =	`pkg-config --cflags glib-2.0` \
			`pkg-config --cflags gthread-2.0`
CFLAGS = -Wall -O $(INCLUDES) -W -Wextra
scholarzhang: scholarzhang.c
	$(CC) $(CFLAGS) $(LIBS) -o $@ $<

.PHONY: clean

clean: 
	rm -f *.o scholarzhang
