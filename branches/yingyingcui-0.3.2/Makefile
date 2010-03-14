CC = gcc
LIBS =		`libnet-config --libs` \
		`pcap-config --libs` -lpthread
CFLAGS = -Wall -O $(INCLUDES) -W -Wextra -g
yingyingcui: yingyingcui.c
	$(CC) $(CFLAGS) $(LIBS) -o $@ $<

.PHONY: clean

clean: 
	rm -f *.o yingyingcui
