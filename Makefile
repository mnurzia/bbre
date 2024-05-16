.SILENT: help_targets

CFLAGS=-Wall -Werror -Wextra -Wshadow -pedantic -Wuninitialized -std=c89 -fsanitize=address -O0 -g
CFLAGS_COV=--coverage

SRCS=re.c test.c test-gen.c
GDB=lldb --
FORMAT=clang-format -i
UDATA=python tools/unicode_data.py --debug --db tools/.ucd.zip

FUZZINGTON=build/fuzzington/release/fuzzington
OPEN_URL=python -m webbrowser

## run target `test`
all: test

## remove build files
clean:
	rm -rf build

build:
	mkdir -p build/{cov,fuzz/{artifact,new},fuzzington}

build/test: build $(SRCS)
	$(CC) $(CFLAGS) -DRE_TEST $(SRCS) -o $@

test-gen.c: build fuzz_db.json tools/fuzz_tool.py
	$(UDATA) gen_ascii_charclasses test test-gen.c
	python tools/fuzz_tool.py fuzz_db.json gen_tests test-gen.c
	$(FORMAT) $@

build/compile_commands.json: build $(SRCS) 
	bear --output $@ -- make -B build/test build/parser_fuzz build/fuzzington_harness

## generate compile_commands.json for language servers (alias for build/compile_commands.json)
compile_commands: build/compile_commands.json

## run tests
test: build/test
	./build/test

## run tests in a debugger
testdbg: build/test
	$(GDB) ./build/test

## run tests with OOM checking
testoom: build/test
	./build/test --leak-check --fault-check

## run tests with OOM checking in a debugger
testdbgoom: build/test
	$(GDB) ./build/test --leak-check --fault-check

## run the given test
test_%: build/test
	./build/test -t $(subst test_,,$@)

## run the given test in a debugger
testdbg_%: build/test
	$(GDB) ./build/test -t $(subst testdbg_,,$@)

## run the given test with OOM checking
testoom_%: build/test
	./build/test -t $(subst testoom_,,$@) --leak-check --fault-check

## run the given test with OOM checking in a debugger
testdbgoom_%: build/test
	$(GDB) ./build/test -t $(subst testdbgoom_,,$@) --leak-check --fault-check

build/cov/re-cov: build $(SRCS)
	rm -rf build/*.gcda build/*.gcno
	$(CC) $(CFLAGS) -DRE_COV -DRE_TEST -DNDEBUG $(CFLAGS_COV) $(SRCS) -o $@

build/cov/lcov.info: build build/cov/re-cov
	rm -rf $@ build/cov/*.gcda
	cd build/cov; ./re-cov --leak-check --fault-check
	lcov --rc lcov_branch_coverage=1 --directory build/cov --base-directory . --capture --exclude test -o $@

build/cov/index.html: build/cov/lcov.info
	genhtml build/cov/lcov.info --branch-coverage --output-directory build/cov

## run coverage tests (alias for build/cov/lcov.info)
cov: build/cov/lcov.info

## generate coverage html report and open in browser
cov_html: build/cov/index.html
	$(OPEN_URL) file://$(realpath build/cov/reee/re.c.gcov.html)

build/parser_fuzz: build parser_fuzz.c re.c re.h
	$(CC) $(CFLAGS) -fsanitize=fuzzer,address re.c parser_fuzz.c -o $@

## run the LLVM fuzzer on the parser
parser_fuzz: build build/parser_fuzz
	./build/parser_fuzz -artifact_prefix=build/fuzz/artifact/ -timeout=5 build/fuzz build/fuzz/new

## import generated LLVM fuzzer artifacts as tests
parser_fuzz_import: build
	$(UDATA) add_parser_fuzz_regression_tests fuzz_results.json build/fuzz/artifact/*

build/fuzzington/release/fuzzington: tools/fuzzington/src/main.rs tools/fuzzington/build.rs
	cd tools/fuzzington; cargo build --release --target-dir ../../build/fuzzington

## run fuzzington, the semantic regex fuzz tester
fuzzington_run: build build/fuzzington/release/fuzzington
	python tools/fuzz_tool.py --debug fuzz_db.json run_fuzzington --num-iterations 1000000

## generate data tables for re.c
tables:
	$(UDATA) gen_casefold re.c
	$(UDATA) gen_ascii_charclasses impl re.c
	$(FORMAT) re.c

## run clang-format/black on all .c/.py sources
format:
	$(FORMAT) $(SRCS) parser_fuzz.c
	python -m black -q tools/*.py

build/viz: build viz.c re.c
	$(CC) $(CFLAGS) viz.c re.c -o $@

viz_gv_%:
	TVIZ=$$(mktemp); ./build/viz $(subst viz_gv_,,$@) | dot -Tsvg > "$$TVIZ"; $(OPEN_URL) file://$$(realpath $$TVIZ); sleep 0.5; rm -rf $$TVIZ

## visualize a regex's compiled program (use `echo "regex" | make viz_prog`)
viz_prog: build/viz viz_gv_prog

## visualize a regex's AST (use `echo "regex" | make viz_ast`)
viz_ast: build/viz viz_gv_ast

## print a list of targets and their descriptions
help_targets:
	awk 'BEGIN {print "TARGET&DESCRIPTION"} {if ($$0 ~ /^##/) {getline target; split(target,a,":"); print a[1]"&"substr($$0,4)}}' Makefile | sort | column -t -s '&'

## build documentation
docs: build build/viz
	python tools/make_docs.py --folder docs --debug re.c internals/AST.md
	python tools/make_docs.py --folder docs --debug re.c internals/Charclass_Compiler.md
