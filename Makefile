CC=gcc
CFLAGS=-O2 -flto -s
LDFLAGS=-Wall -flto -O2 -Wextra -Wall -Wpedantic -D_FORTIFY_SOURCE=2 -fdata-sections -ffunction-sections -Wl,-z,relro,-z,now -fsanitize=address -fPIE -pie -fstack-protector-strong -fcf-protection=full -mshstk
PREFIX = /usr
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin

all : build

build : Listener

Listener: main.o
	$(CC) -o ./Listener ./main.o $(CFLAGS)

main.o :
	$(CC) $(LDFLAGS) -c ./main.c -o ./main.o

install:
	cp ./Listener $(BINDIR)

clean:
	rm ./main.o
