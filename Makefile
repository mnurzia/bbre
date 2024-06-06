.SILENT: help_targets help_profiles

# default profile: debug
PROFILE=debug

CFLAGS_debug=-O0 -g -fsanitize=address,undefined
CFLAGS_noopt=-O0 -g -DNDEBUG
CFLAGS_bench=-O3 -g -DNDEBUG
CFLAGS_opt=-O3 -DNDEBUG
CFLAGS_optopt=-Ofast -DNDEBUG
CFLAGS_cov=-O0 --coverage -DRE_COV -DNDEBUG

# tell em to bring out the whole... set of compiler flags!
CFLAGS=\
			 -Wall\
			 -Werror\
			 -Wextra\
			 -Wshadow\
			 -pedantic\
			 -Wuninitialized\
			 -Wunused-variable\
			 -std=c89\
			 $(CFLAGS_$(PROFILE))

SRCS=re.c test.c test-gen.c
GDB=lldb --
FORMAT=clang-format -i
UDATA=python tools/unicode_data.py --debug --db tools/.ucd.zip

FUZZINGTON=build/fuzzington/release/fuzzington
FUZZINGTON_ITERS=10000000
OPEN_URL=python -m webbrowser

OUT_DIR=build/$(PROFILE)

## run target `test`
all: test

## remove build files
clean:
	rm -rf build

build:
	mkdir -p build/{cov,fuzz/{artifact,new},fuzzington}

test-gen.c: build fuzz_db.json tools/fuzz_tool.py
	$(UDATA) gen_ccs test test-gen.c
	python tools/fuzz_tool.py fuzz_db.json gen_tests test-gen.c
	$(FORMAT) $@

$(OUT_DIR): build
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/mptest.o: $(OUT_DIR) mptest.c
	$(CC) $(CFLAGS) mptest.c -c -o $@

$(OUT_DIR)/re.o: $(OUT_DIR) re.c
	$(CC) $(CFLAGS) -DRE_CONFIG_HEADER_FILE=\"test-config.h\" re.c -c -o $@

$(OUT_DIR)/test.o: $(OUT_DIR) test.c
	$(CC) $(CFLAGS) test.c -c -o $@

$(OUT_DIR)/test-gen.o: $(OUT_DIR) test-gen.c
	$(CC) $(CFLAGS) test-gen.c -c -o $@

$(OUT_DIR)/re_test: $(OUT_DIR)/mptest.o $(OUT_DIR)/re.o $(OUT_DIR)/test.o $(OUT_DIR)/test-gen.o
	$(CC) $(CFLAGS) $(OUT_DIR)/mptest.o $(OUT_DIR)/re.o $(OUT_DIR)/test.o $(OUT_DIR)/test-gen.o -o $@

$(OUT_DIR)/re.S: $(OUT_DIR) re.c
	$(CC) $(CFLAGS) re.c -S -fverbose-asm -o $@

## run tests
test: $(OUT_DIR)/re_test
	./$(OUT_DIR)/re_test

## run tests in a debugger
testdbg: $(OUT_DIR)/re_test
	$(GDB) ./$(OUT_DIR)/re_test

## run tests with OOM checking
testoom: $(OUT_DIR)/re_test
	./$(OUT_DIR)/re_test --leak-check --fault-check

## run tests with OOM checking in a debugger
testdbgoom: $(OUT_DIR)/re_test
	$(GDB) ./$(OUT_DIR)/re_test --leak-check --fault-check

## run the given test
test_%: $(OUT_DIR)/re_test
	./$(OUT_DIR)/re_test -t $(subst test_,,$@)

## run the given test in a debugger
testdbg_%: $(OUT_DIR)/re_test
	$(GDB) ./$(OUT_DIR)/re_test -t $(subst testdbg_,,$@)

## run the given test with OOM checking
testoom_%: $(OUT_DIR)/re_test
	./$(OUT_DIR)/re_test -t $(subst testoom_,,$@) --leak-check --fault-check

## run the given test with OOM checking in a debugger
testdbgoom_%: $(OUT_DIR)/re_test
	$(GDB) ./$(OUT_DIR)/re_test -t $(subst testdbgoom_,,$@) --leak-check --fault-check

build/compile_commands.json: build
	bear --output $@ -- make -B build/$(PROFILE)/re_test

## generate build/compile_commands.json for language servers 
compile_commands: build/compile_commands.json

build/cov/lcov.info: build/$(PROFILE)/re_test
	$(MAKE) PROFILE=cov build/cov/re_test
	rm -rf $@ build/cov/*.gcda
	cd build/cov; ./re_test --leak-check --fault-check
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

$(OUT_DIR)/bench.o: $(OUT_DIR) bench.c re.c re.h
	$(CC) $(CFLAGS) bench.c -c -o $@

$(OUT_DIR)/re-bench.o: $(OUT_DIR) re.c re.h
	$(CC) $(CFLAGS) re.c -c -o $@

$(OUT_DIR)/bench: $(OUT_DIR)/bench.o $(OUT_DIR)/re-bench.o
	$(CC) $(CFLAGS) $(OUT_DIR)/bench.o $(OUT_DIR)/re-bench.o -o $@

## run benchmarks
bench: $(OUT_DIR)/bench
	./$(OUT_DIR)/bench

## profile benchmarks
prof: $(OUT_DIR)/bench
	samply record ./$(OUT_DIR)/bench

build/fuzzington/release/fuzzington: tools/fuzzington/src/main.rs tools/fuzzington/build.rs
	cd tools/fuzzington;RUSTFLAGS="-C link-dead-code" cargo build --release --target-dir ../../build/fuzzington

## run fuzzington, the semantic regex fuzz tester
fuzzington_run: build build/fuzzington/release/fuzzington
	python tools/fuzz_tool.py --debug fuzz_db.json run_fuzzington --num-iterations $(FUZZINGTON_ITERS)

## generate data tables for re.c
tables:
	$(UDATA) gen_casefold re.c
	python3 tools/charclass_tree.py dfa re.c
	$(UDATA) gen_ccs impl re.c
	$(FORMAT) re.c

## run clang-format/black on all .c/.py sources
format:
	$(FORMAT) re.c re.h test-gen.c test.c test-config.h viz.c parser_fuzz.c
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

## print a list of profiles
help_profiles:
	sed < Makefile -n -e '1s/^.*/PROFILE\&CFLAGS/p' -e 's/CFLAGS_\([a-z]*\)=\(.*\)/\1\&\2/p' | column -t -s '&'

## build documentation
docs: build build/viz
	python tools/make_docs.py --folder docs --debug re.c internals/AST.md
	python tools/make_docs.py --folder docs --debug re.c internals/Charclass_Compiler.md

## build a folder with re + tests for testing on other platforms
port: build re.c test.c test-gen.c mptest.c mptest.h test-config.h re.h
	mkdir -p build/port
	cp -f tools/port/* build/port
	cp -f re.c test.c test-gen.c mptest.c mptest.h test-config.h re.h build/port
