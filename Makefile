CFLAGS=-Wall -Werror -Wextra -pedantic -std=c89 -O0 -g

all: re

re: re.c test.c
	gcc $(CFLAGS) re.c test.c -o re

clean:
	rm -rf re
