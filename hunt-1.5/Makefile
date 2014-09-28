CFLAGS=-Wall -O2 -g -D_REENTRANT
#CFLAGS+=-DSYNC_FAST
#CFLAGS+=-D_WITH_LINUX_KERNEL_HDR

LDFLAGS=
#LDFLAGS=-static

OBJ=hunt.o main.o c/list.o c/hash.o c/array.o util.o net.o \
	rst.o menu.o hijack.o rstd.o sniff.o macdisc.o \
	tap.o arphijack.o tty.o synchijack.o arpspoof.o hostup.o \
	addpolicy.o options.o resolv.o timer.o pktrelay.o
	
hunt: $(OBJ)
	$(CC) ${LDFLAGS} -o $@ $^ -lpthread

hunt_static: $(OBJ)
	$(CC) ${LDFLAGS} -static -o $@ $^ -lpthread

all: hunt hunt_static

dist: all clean
	strip hunt
	strip hunt_static

clean:
	rm -f *.o core c/*.o c/core c/list_test c/hash_test c/array_test
	$(MAKE) -C tpserv clean
#	rm -rf .sniff
	
distclean:
	rm -f *.o core c/*.o c/core c/list_test c/hash_test c/array_test
	rm -f hunt hunt_static
	$(MAKE) -C tpserv distclean
#	rm -rf .sniff

cleandist: distclean

clean-dist: distclean

dist-clean: distclean

