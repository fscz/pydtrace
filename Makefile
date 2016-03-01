CC = gcc
AR = ar
CFLAGS = -Wall -g -O3 -I/usr/include/python2.7 
LDFLAGS = -shared -lm -lpython -ldtrace
objects := $(patsubst %.c,%.o,$(wildcard *.c))

all: dtrace.so 

.PHONY: clean

clean:
	rm *.o
	rm *~
	rm dtrace.so

%.o: %.c
	${CC} ${CFLAGS} -c $<

dtrace.so: $(objects)
	$(CC) -o $@ $^ $(LDFLAGS) 
