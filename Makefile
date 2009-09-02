CC = gcc
LIBS =	-lglib-2.0 -lnet -lwpcap -lws2_32
INCLUDES = -I/mingw/include/glib-2.0 -I/mingw/lib/glib-2.0/include 
CFLAGS = -Wall -O2 $(INCLUDES) -W -Wextra -mms-bitfields
scholarzhang.exe: scholarzhang.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean: 
	rm -f *.o scholarzhang.exe
