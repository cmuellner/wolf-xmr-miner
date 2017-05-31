CC = gcc
LD = gcc
OPT = -O3
CFLAGS = -D_POSIX_SOURCE -D_GNU_SOURCE $(OPT) -pthread -c -std=c11 -march=armv8-a+crypto
LDFLAGS	= -pthread $(OPT)
LIBS = -ljansson

OBJS	= crypto/c_blake256.o crypto/c_groestl.o \
	crypto/c_keccak.o crypto/c_jh.o crypto/c_skein.o \
	cryptonight.o log.o net.o minerutils.o main.o

all:	$(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o miner

clean:
	rm -f *.o crypto/*.o miner
