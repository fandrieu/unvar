CC = gcc
CFLAGS = -Wall -D_LARGEFILE64_SOURCE -O3
PROGRAMS = unvar quicklz
all : $(PROGRAMS)
unvar : unvar.c quicklz.c md5.c
	$(CC) $(CFLAGS) -o unvar $^ $(LDFLAGS)
	$(CC) $(CFLAGS) -static -o unvar-static $^ $(LDFLAGS)
	$(CC) $(CFLAGS) -fno-stack-protector -o unvar-ns $^ $(LDFLAGS)
quicklz : quicklz.c
	$(CC) $(CFLAGS) -shared -fPIC -o quicklz.so $^ $(LDFLAGS)
clean:
	rm unvar unvar-static unvar-ns quicklz.so pyquicklz.pyc
