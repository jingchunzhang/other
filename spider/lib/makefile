CC=gcc
CXX=g++
INC+= -I../include -I/data/spider/scws/include/scws
LIB+= -lpthread -ldl -lrt -rdynamic 
CFLAGS+= -g -O2 -pipe -Wall -fno-strict-aliasing -D_GNU_SOURCE -D_REENTRANT 
TARGET=libmyshm.a
ALL:$(TARGET)

OBJ = myshm.o \
	  myrindex.o \
	  myhash.o \
	  uselist.o \
	  split.o \
	  common.o \
	  myconfig.o \
	  log.o \
	  myconv.o

$(TARGET):$(OBJ)
	ar rv $@ $(OBJ)
#	install $(TARGET) ../bin
%.o: %.cpp
	$(CXX)  $(CFLAGS) $(INC) -c -o $@ $< 	 
%.o: %.c
	$(CC)  $(CFLAGS) $(INC) -c -o $@ $< 	 
clean:
	rm -f $(OBJ)
	rm -f $(TARGET) 	
