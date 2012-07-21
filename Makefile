CC = gcc
CFLAGS = -Wall -D_LARGEFILE64_SOURCE -O3
PROGRAMS = unvar
all : $(PROGRAMS)
unvar : unvar.c quicklz.c
	$(CC) $(CFLAGS) -o unvar $^ $(LDFLAGS)
clean:
	rm unvar
