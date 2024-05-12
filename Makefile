CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -fsanitize=address -ferror-limit=0 -Wuninitialized -std=c89 -O0 -g
COVCFLAGS=--coverage

SRCS=re.c test.c test-gen.c
GDB=lldb --

## run target `test`
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

## run tests
test: build/re
	./build/re

## run tests in a debugger
testdbg: build/re
	$(GDB) ./build/re

## run tests with OOM checking
testoom: build/re
	./build/re --leak-check --fault-check

## run tests with OOM checking in a debugger
testdbgoom: build/re
	$(GDB) ./build/re --leak-check --fault-check

## run the given test
test_%: build/re
	./build/re -t $(subst test_,,$@)

## run the given test in a debugger
testdbg_%: build/re
	$(GDB) ./build/re -t $(subst debug_test_,,$@)

## run the given test with OOM checking
testoom_%: build/re
	./build/re -t $(subst testoom_,,$@) --leak-check --fault-check

## run the given test with OOM checking in a debugger
testdbgoom_%: build/re
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

## build and open a coverage report
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

## run the LLVM fuzzer on the parser
parser_fuzz: corpus corpus/new corpus/artifact build/parser_fuzz
	./build/parser_fuzz -artifact_prefix=corpus/artifact/ -timeout=5 corpus corpus/new

## import generated LLVM fuzzer artifacts as tests
parser_fuzz_import: corpus/artifact
	python tools/unicode_data.py --debug add_parser_fuzz_regression_tests fuzz_results.json corpus/artifact/*

tools/.ucd.zip:
	python tools/unicode_data.py --debug --db tools/.ucd.zip fetch

## generate data tables for re.c
tables: tools/.ucd.zip
	python tools/unicode_data.py --debug --db tools/.ucd.zip gen_casefold re.c
	python tools/unicode_data.py --debug --db tools/.ucd.zip gen_ascii_charclasses impl re.c
	clang-format -i re.c

## run clang-format on all sources
format:
	clang-format -i $(SRCS) parser_fuzz.c

## remove build files
clean:
	rm -rf build corpus

.SILENT: targets

## print a list of targets and their descriptions
targets:
	awk 'BEGIN {print "TARGET,DESCRIPTION"} {if ($$0 ~ /^##/) {getline target; split(target,a,":"); print a[1]","substr($$0,4)}}' Makefile | column -t -s ',' | sort
