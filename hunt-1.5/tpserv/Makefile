CC=egcs
CFLAGS=-Wall -O2 -g

all: tpserv

tpserv: tpserv.o
	$(CC) -o $@ $< $(LIBS)

clean:
	rm -f *.o

distclean: clean
	rm -f tpserv
