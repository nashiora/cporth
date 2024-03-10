CC = clang

CFLAGS = -std=c23 -pedantic -pedantic-errors -fsanitize=address -ggdb -Werror=return-type
LDFLAGS = 

all: porthc

porthc: main.c porth.c porth.h
	$(CC) -o porthc main.c porth.c $(CFLAGS) $(LDFLAGS)

clean:
	rm porthc
