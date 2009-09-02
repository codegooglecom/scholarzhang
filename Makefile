CC = gcc
LIBS =	-lnet -lwpcap -lws2_32
INCLUDES = 
CFLAGS = -Wall -O2 $(INCLUDES) -W -Wextra 
scholarzhang.exe: scholarzhang.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean: 
	rm -f *.o scholarzhang.exe
