CC = clang

CFLAGS = -std=c2x -pedantic -pedantic-errors -Werror=all -Werror=extra -Wno-error=unused -Wno-error=unused-value -Wno-error=unused-parameter -Wno-unused-function -fsanitize=address -ggdb
LDFLAGS = -fsanitize=address

all: porthc

porthc: main.c porth.c porth.h
	$(CC) -o porthc main.c porth.c $(CFLAGS) $(LDFLAGS)

clean:
	rm porthc
