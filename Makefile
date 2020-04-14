#
# FILE : Makefile
#
# Purpose : compile the program

#compile flags
CFLAGS =-g -Wall

all: ping

ping: ping.c
		cc ${CFLAGS} ping.c -o ping
	
clean:
	rm -f
