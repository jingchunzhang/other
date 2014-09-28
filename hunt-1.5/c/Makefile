CFLAGS=-Wall -g

PROGS = list_test hash_test array_test

all: ${PROGS}



list_test: list_test.o
	gcc -o $@ $^ -lpthread

list_test.o: list.c list.h 
	gcc -c $(CFLAGS) -DTEST -D_REENTRANT -o $@ $<

hash_test: hash_test.o
	gcc -o $@ $^ -lpthread

hash_test.o: hash.c hash.h 
	gcc -c $(CFLAGS) -DTEST -D_REENTRANT -o $@ $<

array_test: array_test.o
	gcc -o $@ $^ -lpthread

array_test.o: array.c array.h
	gcc -c $(CFLAGS) -DTEST -D_REENTRANT -o $@ $<

clean:
	rm -f ${PROGS} *.o core
