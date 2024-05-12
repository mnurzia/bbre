CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -Wuninitialized -std=c89 -fsanitize=address -O0 -g
CFLAGS_COV=--coverage

SRCS=re.c test.c test-gen.c
GDB=lldb --
FORMAT=clang-format -i
UDATA=python tools/unicode_data.py --debug --db tools/.ucd.zip

## run target `test`
all: test

## remove build files
clean:
	rm -rf build

build:
	mkdir -p build/{cov,fuzz/{artifact,new}}

build/re: build $(SRCS)
	$(CC) $(CFLAGS) -DRE_TEST $(SRCS) -o $@

test-gen.c: build fuzz_results.json
	$(UDATA) gen_ascii_charclasses test test-gen.c
	$(UDATA) gen_parser_fuzz_regression_tests fuzz_results.json test-gen.c
	$(FORMAT) $@

build/compile_commands.json: build $(SRCS) 
	bear --output $@ -- make -B build/re build/parser_fuzz

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
	$(CC) $(CFLAGS) -DRE_COV -DRE_TEST -DNDEBUG $(CFLAGS_COV) $(SRCS) -o $@

build/cov/lcov.info: build/cov build/cov/re-cov
	rm -rf $@ build/cov/*.gcda
	cd build/cov; ./re-cov --leak-check --fault-check
	lcov --rc lcov_branch_coverage=1 --directory build/cov --base-directory . --capture --exclude test -o $@

build/cov/index.html: build/cov/lcov.info
	genhtml build/cov/lcov.info --branch-coverage --output-directory build/cov

## run coverage and show a coverage report
cov: build/cov/index.html
	python -m webbrowser file://$(realpath build/cov/reee/re.c.gcov.html)

build/parser_fuzz: build parser_fuzz.c re.c re.h
	$(CC) $(CFLAGS) -fsanitize=fuzzer,address re.c parser_fuzz.c -o $@

## run the LLVM fuzzer on the parser
parser_fuzz: build build/parser_fuzz
	./build/parser_fuzz -artifact_prefix=build/fuzz/artifact/ -timeout=5 build/fuzz build/fuzz/new

## import generated LLVM fuzzer artifacts as tests
parser_fuzz_import: build
	$(UDATA) add_parser_fuzz_regression_tests fuzz_results.json build/fuzz/artifact/*

## generate data tables for re.c
tables:
	$(UDATA) gen_casefold re.c
	$(UDATA) gen_ascii_charclasses impl re.c
	$(FORMAT) re.c

## run clang-format on all sources
format:
	$(FORMAT) $(SRCS) parser_fuzz.c

.SILENT: help_targets

## print a list of targets and their descriptions
help_targets:
	awk 'BEGIN {print "TARGET,DESCRIPTION"} {if ($$0 ~ /^##/) {getline target; split(target,a,":"); print a[1]","substr($$0,4)}}' Makefile | column -t -s ',' | sort
