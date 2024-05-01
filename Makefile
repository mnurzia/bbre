CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -fsanitize=address -ferror-limit=0 -Wuninitialized -std=c89 -O0 -g

all: re

re: re.c test.c
	$(CC) $(CFLAGS) re.c test.c -o $@

compile_commands.json: re.c test.c
	bear -- make -B re

debug: re
	lldb re

clean:
	rm -rf re
