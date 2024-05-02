CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -fsanitize=address -ferror-limit=0 -Wuninitialized -std=c89 -O0 -g
COVCFLAGS=--coverage

all: build/re

build:
	mkdir -p build

build/re: build re.c test.c
	$(CC) $(CFLAGS) re.c test.c -o $@

re-cov: build re.c test.c
	$(CC) $(CFLAGS) $(COVCFLAGS) re.c test.c -o $@

build/re-cov: build re.c test.c
	rm -rf build/*.gcda build/*.gcno 
	$(CC) $(CFLAGS) $(COVCFLAGS) re.c test.c -o $@

build/compile_commands.json: build re.c test.c
	bear -- make -B re

test: build/re
	./build/re

build/lcov.info: build/re-cov
	rm -rf build/lcov.info
	./build/re-cov
	lcov --directory build --base-directory . --capture -o build/lcov.info

test_%: build/re
	./build/re -t $(subst test_,,$@)

debug_test_%: build/re
	lldb -- ./build/re -t $(subst debug_test_,,$@)

clean:
	rm -rf build
