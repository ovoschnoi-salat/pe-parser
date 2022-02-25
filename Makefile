CFLAGS=--std=c99 -Wall -pedantic -Isrc/ -ggdb -Wextra -DDEBUG
BUILDDIR=build
CC=gcc

all: $(BUILDDIR)/main.o
	$(CC) -o pe-parser $^

$(BUILDDIR)/main.o: main.c
	mkdir -p $(BUILDDIR)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -rf $(BUILDDIR)