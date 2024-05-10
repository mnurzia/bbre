CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -fsanitize=address -ferror-limit=0 -Wuninitialized -std=c89 -O0 -g -DRE_TEST
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

build/test-gen.c: build test-gen.c tools/unicode_data.py
	cp test-gen.c $@
	python tools/unicode_data.py gen_ascii_charclasses test build/test-gen.c
	clang-format -i $@

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
	$(CC) $(CFLAGS) -DRE_COV -DNDEBUG $(COVCFLAGS) $(SRCS) -o $@

build/cov/lcov.info: build/cov build/cov/re-cov
	rm -rf $@ build/cov/*.gcda
	cd build/cov; ./re-cov --leak-check --fault-check
	lcov --rc lcov_branch_coverage=1 --directory build/cov --base-directory . --capture --exclude test -o $@

build/cov/index.html: build/cov/lcov.info
	genhtml build/cov/lcov.info --branch-coverage --output-directory build/cov

tools/.ucd.zip:
	python tools/unicode_data.py --debug --db tools/.ucd.zip fetch

tables: tools/.ucd.zip
	python tools/unicode_data.py --debug --db tools/.ucd.zip gen_casefold re.c
	python tools/unicode_data.py --debug --db tools/.ucd.zip gen_ascii_charclasses impl re.c
	clang-format -i re.c

format:
	clang-format -i $(SRCS) test-gen.c

cov: build/cov/index.html
	open build/cov/reee/re.c.gcov.html

clean:
	rm -rf build
