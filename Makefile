CC = gcc
CFLAGS = -Wall -D_LARGEFILE64_SOURCE -O3
PROGRAMS = unvar
all : $(PROGRAMS)
unvar : unvar.c quicklz.c md5.c
	$(CC) $(CFLAGS) -o unvar $^ $(LDFLAGS)
	$(CC) $(CFLAGS) -static -o unvar-static $^ $(LDFLAGS)
	$(CC) $(CFLAGS) -fno-stack-protector -o unvar-ns $^ $(LDFLAGS)
clean:
	rm unvar unvar-static unvar-ns
