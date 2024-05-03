CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -fsanitize=address -ferror-limit=0 -Wuninitialized -std=c89 -O0 -g
COVCFLAGS=--coverage

SRCS=re.c test.c build/test-gen.c

all: test

build:
	mkdir -p build

build/re: build $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@

build/test-gen.c: build tools/make_ascii_classes.py
	python tools/make_ascii_classes.py tests | clang-format > $@

re-cov: build $(SRCS)
	$(CC) $(CFLAGS) $(COVCFLAGS) $(SRCS) -o $@

build/re-cov: build $(SRCS)
	rm -rf build/*.gcda build/*.gcno 
	$(CC) $(CFLAGS) $(COVCFLAGS) $(SRCS) -o $@

build/compile_commands.json: build $(SRCS) 
	bear --output $@ -- make -B build/re

test: build/re
	./build/re

testoom: build/re
	./build/re --leak-check --fault-check

build/lcov.info: build/re-cov
	rm -rf build/lcov.info
	./build/re-cov
	lcov --directory build --base-directory . --capture -o build/lcov.info

test_%: build/re
	./build/re -t $(subst test_,,$@)

debug_test_%: build/re
	lldb -- ./build/re -t $(subst debug_test_,,$@)

testoom_%: build/re
	./build/re -t $(subst testoom_,,$@) --leak-check --fault-check

debug_testoom_%: build/re
	lldb -- ./build/re -t $(subst debug_testoom_,,$@) --leak-check --fault-check

clean:
	rm -rf build
