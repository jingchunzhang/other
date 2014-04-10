CC=gcc
CXX=g++
INC+= -I../include -I/data/spider/scws/include/scws
LIB+= -lpthread -ldl -lrt -rdynamic -liconv -L../lib -lmyshm -L/data/spider/scws/lib/ -lscws
CFLAGS+= -g -O2 -pipe -Wall -fno-strict-aliasing -D_GNU_SOURCE -D_REENTRANT 
TARGET=spider
ALL:$(TARGET)

OBJ = app.o \
	  netdata.o \
	  mm.o \
	  urlcode.o \
	  appchina.o \
	  sj.o \
	  hiapk.o \
	  androidcn.o 

$(TARGET):$(OBJ)
	$(CC)	$(CFLAGS) -o $@ $^ $(LIB)
#	install $(TARGET) ../bin
%.o: %.cpp
	$(CXX)  $(CFLAGS) $(INC) -c -o $@ $< 	 
%.o: %.c
	$(CC)  $(CFLAGS) $(INC) -c -o $@ $< 	 
clean:
	rm -f $(OBJ)
	rm -f $(TARGET) 	
