CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -fsanitize=address -ferror-limit=0 -Wuninitialized -std=c89 -O0 -g
COVCFLAGS=--coverage

SRCS=re.c test.c test-gen.c
GDB=lldb --

all: test

build:
	mkdir -p build

build/cov:
	mkdir -p build/cov

build/re: build $(SRCS)
	$(CC) $(CFLAGS) -DRE_TEST $(SRCS) -o $@

test-gen.c: build tools/unicode_data.py fuzz_results.json
	python tools/unicode_data.py gen_ascii_charclasses test test-gen.c
	python tools/unicode_data.py gen_parser_fuzz_regression_tests fuzz_results.json test-gen.c
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
	$(CC) $(CFLAGS) -DRE_COV -DNDEBUG -DRE_TEST $(COVCFLAGS) $(SRCS) -o $@

build/cov/lcov.info: build/cov build/cov/re-cov
	rm -rf $@ build/cov/*.gcda
	cd build/cov; ./re-cov --leak-check --fault-check
	lcov --rc lcov_branch_coverage=1 --directory build/cov --base-directory . --capture --exclude test -o $@

build/cov/index.html: build/cov/lcov.info
	genhtml build/cov/lcov.info --branch-coverage --output-directory build/cov

cov: build/cov/index.html
	open build/cov/reee/re.c.gcov.html

build/parser_fuzz: build parser_fuzz.c re.c re.h
	$(CC) $(CFLAGS) -fsanitize=fuzzer,address re.c parser_fuzz.c -o $@

corpus:
	mkdir -p corpus

corpus/new: corpus
	mkdir -p corpus/new

corpus/artifact: corpus
	mkdir -p corpus/artifact

parser_fuzz: corpus corpus/new corpus/artifact build/parser_fuzz
	./build/parser_fuzz -artifact_prefix=corpus/artifact/ corpus corpus/new

parser_fuzz_import: corpus/artifact
	python tools/unicode_data.py --debug add_parser_fuzz_regression_tests fuzz_results.json corpus/artifact/*

tools/.ucd.zip:
	python tools/unicode_data.py --debug --db tools/.ucd.zip fetch

tables: tools/.ucd.zip
	python tools/unicode_data.py --debug --db tools/.ucd.zip gen_casefold re.c
	python tools/unicode_data.py --debug --db tools/.ucd.zip gen_ascii_charclasses impl re.c
	clang-format -i re.c

format:
	clang-format -i $(SRCS) test-gen.c


clean:
	rm -rf build corpus
