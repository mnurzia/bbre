CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -fsanitize=address -ferror-limit=0 -Wuninitialized -std=c89 -O0 -g
COVCFLAGS=--coverage

SRCS=re.c test.c build/test-gen.c
GDB=lldb --

all: test

build:
	mkdir -p build

build/cov:
	mkdir -p build/cov

build/re: build $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@

build/test-gen.c: build tools/make_ascii_classes.py
	python tools/make_ascii_classes.py tests | clang-format > $@

build/compile_commands.json: build $(SRCS) 
	bear --output $@ -- make -B build/re

test: build/re
	./build/re

debug_test: build/re
	$(GDB) ./build/re

testoom: build/re
	./build/re --leak-check --fault-check

debug_testoom: build/re
	$(GDB) ./build/re --leak-check --fault-check

test_%: build/re
	./build/re -t $(subst test_,,$@)

debug_test_%: build/re
	$(GDB) ./build/re -t $(subst debug_test_,,$@)

testoom_%: build/re
	./build/re -t $(subst testoom_,,$@) --leak-check --fault-check

debug_testoom_%: build/re
	$(GDB) ./build/re -t $(subst debug_testoom_,,$@) --leak-check --fault-check

build/cov/re-cov: build $(SRCS)
	rm -rf build/*.gcda build/*.gcno 
	$(CC) $(CFLAGS) -DRE_COV $(COVCFLAGS) $(SRCS) -o $@

build/cov/lcov.info: build/cov build/cov/re-cov
	rm -rf $@ build/cov/*.gcda
	cd build/cov; ./re-cov --leak-check --fault-check
	lcov --directory build/cov --base-directory . --capture --exclude test -o $@

build/cov/index.html: build/cov/lcov.info
	genhtml build/cov/lcov.info --output-directory build/cov

clean:
	rm -rf build
