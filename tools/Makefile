# This is a long and dense Makefile. If you need help figuring out how to use
# this, run `make help_targets`.
.SILENT: help_targets help_profiles loc

# default profile: debug
PROFILE=debug

# For each profile, define a new CFLAGS and it will be used throughout the Makefile.
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
	-DBBRE_DEBUG_UTILS=\"tools/debug_utils.c\"\
	$(CFLAGS_$(PROFILE))

GDB=ASAN_OPTIONS=halt_on_error=0 lldb --
FORMAT=clang-format -i
PYTHON=/usr/bin/env python3
UDATA=$(PYTHON) scripts/unicode_data.py --debug --db scripts/.ucd.zip

FUZZINGTON=build/fuzzington/release/fuzzington
FUZZINGTON_ITERS=10000000
OPEN_URL=$(PYTHON) -m webbrowser

OUT_DIR=build/$(PROFILE)
BBRE_C=../bbre.c
BBRE_H=../bbre.h

DOCS_DIR=../docs

## run target `test`
all: test

## remove build files
clean:
	rm -rf build

build:
	mkdir -p build/{cov,fuzz/{artifact,new},fuzzington}

test_gen.c: build fuzz_db.json scripts/fuzz_tool.py scripts/unicode_data.py
	$(UDATA) gen_ccs test test_gen.c
	$(PYTHON) scripts/fuzz_tool.py fuzz_db.json gen_tests test_gen.c
	$(FORMAT) $@

$(OUT_DIR): build
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/mptest.o: $(OUT_DIR) mptest.c
	$(CC) $(CFLAGS) mptest.c -c -o $@

$(OUT_DIR)/bbre.o: $(OUT_DIR) $(BBRE_C)
	$(CC) $(CFLAGS) -DBBRE_CONFIG_HEADER_FILE=\"tools/test_config.h\"\
		$(BBRE_C) -c -o $@

$(OUT_DIR)/test.o: $(OUT_DIR) test.c
	$(CC) $(CFLAGS) test.c -c -o $@

$(OUT_DIR)/test_gen.o: $(OUT_DIR) test_gen.c
	$(CC) $(CFLAGS) test_gen.c -c -o $@

$(OUT_DIR)/bbre_test: $(OUT_DIR)/mptest.o $(OUT_DIR)/bbre.o $(OUT_DIR)/test.o\
		$(OUT_DIR)/test_gen.o
	$(CC) $(CFLAGS) $(OUT_DIR)/mptest.o $(OUT_DIR)/bbre.o $(OUT_DIR)/test.o\
		$(OUT_DIR)/test_gen.o -o $@

$(OUT_DIR)/re.S: $(OUT_DIR) $(BBRE_C)
	$(CC) $(CFLAGS) $(BBRE_C) -S -fverbose-asm -o $@

## run tests
test: $(OUT_DIR)/bbre_test
	./$(OUT_DIR)/bbre_test

## run tests in a debugger
testdbg: $(OUT_DIR)/bbre_test
	$(GDB) ./$(OUT_DIR)/bbre_test

## run tests with OOM checking
testoom: $(OUT_DIR)/bbre_test
	./$(OUT_DIR)/bbre_test --leak-check --fault-check

## run tests with OOM checking in a debugger
testdbgoom: $(OUT_DIR)/bbre_test
	$(GDB) ./$(OUT_DIR)/bbre_test --leak-check --fault-check

## run the given test
test_%: $(OUT_DIR)/bbre_test
	./$(OUT_DIR)/bbre_test -t $(subst test_,,$@)

## run the given test in a debugger
testdbg_%: $(OUT_DIR)/bbre_test
	$(GDB) ./$(OUT_DIR)/bbre_test -t $(subst testdbg_,,$@)

## run the given test with OOM checking
testoom_%: $(OUT_DIR)/bbre_test
	./$(OUT_DIR)/bbre_test -t $(subst testoom_,,$@) --leak-check\
		--fault-check

## run the given test with OOM checking in a debugger
testdbgoom_%: $(OUT_DIR)/bbre_test
	$(GDB) ./$(OUT_DIR)/bbre_test -t $(subst testdbgoom_,,$@) --leak-check\
		--fault-check

build/compile_commands.json: build
	bear --output $@ -- make -B build/$(PROFILE)/bbre_test

## generate build/compile_commands.json for language servers 
compile_commands: build/compile_commands.json
	mkdir -p ../build # because compile commands needs to be at project root
	cp build/compile_commands.json ../build/compile_commands.json

build/cov/lcov.info: build/$(PROFILE)/bbre_test
	$(MAKE) PROFILE=cov build/cov/bbre_test
	rm -rf $@ build/cov/*.gcda
	cd build/cov; ./bbre_test --leak-check --fault-check
	lcov --rc lcov_branch_coverage=1 --directory build/cov\
		--base-directory . --capture --exclude test -o $@

build/cov/index.html: build/cov/lcov.info
	genhtml build/cov/lcov.info --branch-coverage\
		--output-directory build/cov

## run coverage tests (alias for build/cov/lcov.info)
cov: build/cov/lcov.info

## generate coverage html report and open in browser
cov_html: build/cov/index.html
	$(OPEN_URL) file://$(realpath build/cov/bbre/bbre.c.gcov.html)

build/parser_fuzz: build parser_fuzz.c $(BBRE_C) $(BBRE_H)
	$(CC) $(CFLAGS) -fsanitize=fuzzer,address $(BBRE_C) parser_fuzz.c -o $@

## run the LLVM fuzzer on the parser
parser_fuzz: build build/parser_fuzz
	./build/parser_fuzz -artifact_prefix=build/fuzz/artifact/ -timeout=5\
		build/fuzz build/fuzz/new\
		|| python scripts/fuzz_tool.py fuzz_db.json import_parser\
			build/fuzz/artifact/*

## import generated LLVM fuzzer artifacts as tests
parser_fuzz_import: build
	$(UDATA) add_parser_fuzz_regression_tests fuzz_results.json\
		build/fuzz/artifact/*

$(OUT_DIR)/bench.o: $(OUT_DIR) bench.c $(BBRE_H)
	$(CC) $(CFLAGS) bench.c -c -o $@

$(OUT_DIR)/bbre_bench.o: $(OUT_DIR) $(BBRE_C) $(BBRE_H)
	$(CC) $(CFLAGS) $(BBRE_C) -c -o $@

$(OUT_DIR)/bench: $(OUT_DIR)/bench.o $(OUT_DIR)/bbre_bench.o
	$(CC) $(CFLAGS) $(OUT_DIR)/bench.o $(OUT_DIR)/bbre_bench.o -o $@

## run benchmarks
bench: $(OUT_DIR)/bench
	./$(OUT_DIR)/bench

## profile benchmarks
prof: $(OUT_DIR)/bench
	samply record ./$(OUT_DIR)/bench

## profile a specific benchmark
prof_%: $(OUT_DIR)/bench
	samply record ./$(OUT_DIR)/bench $(subst prof_,,$@)

$(OUT_DIR)/anal: $(OUT_DIR)
	mkdir -p $@

anal: $(OUT_DIR)/anal $(BBRE_C)
	rm -rf $(OUT_DIR)/anal/*.html
	$(CC) $(CFLAGS) --analyze -Xclang -analyzer-output=html\
		-o $(OUT_DIR)/anal $(BBRE_C)

## run static analyzer on the code and display all reports
anal_html: anal
	for name in $(OUT_DIR)/anal/*.html;\
		do $(OPEN_URL) file://$$(realpath $$name);\
	done

## run static analyzer on the code and display the first bug
anal_html_one: anal
	$(OPEN_URL) file://\
		$$(realpath $$(ls -1 $(OUT_DIR)/anal/* | head -n1 | tr -d '\n'))

build/fuzzington/release/fuzzington: fuzzington/src/main.rs fuzzington/build.rs $(BBRE_C) $(BBRE_H) 
	cd fuzzington;RUSTFLAGS="-C link-dead-code" cargo build --release\
		--target-dir ../build/fuzzington

## run fuzzington, the semantic regex fuzz tester
fuzzington_run: build build/fuzzington/release/fuzzington
	$(PYTHON) scripts/fuzz_tool.py --debug fuzz_db.json run_fuzzington\
		--num-iterations $(FUZZINGTON_ITERS)

## generate data tables for re.c
tables:
	$(UDATA) gen_casefold $(BBRE_C)
	$(PYTHON) scripts/charclass_tree.py dfa $(BBRE_C)
	$(UDATA) gen_ccs impl $(BBRE_C)
	$(FORMAT) $(BBRE_C)

## run clang-format/black on all .c/.py sources
format:
	$(FORMAT) $(BBRE_C) $(BBRE_H) bench.c debug_utils.c parser_fuzz.c\
		test.c test_config.h test_gen.c viz.c 
	$(PYTHON) -m black -q scripts/*.py

$(OUT_DIR)/viz: build $(BBRE_C) viz.c
	$(CC) $(CFLAGS) $(BBRE_C) viz.c -o $@

viz_gv_%: $(OUT_DIR)/viz
	TVIZ=$$(mktemp);\
		$(OUT_DIR)/viz $(subst viz_gv_,,$@) | dot -Tsvg > "$$TVIZ";\
		$(OPEN_URL) file://$$(realpath $$TVIZ);\
		sleep 0.5;\
		rm -rf $$TVIZ

## visualize a regex's compiled program (use `echo "regex" | make viz_prog`)
viz_prog: viz_gv_prog

## visualize a regex's AST (use `echo "regex" | make viz_ast`)
viz_ast: viz_gv_ast

## print a list of targets and their descriptions
help_targets:
	awk 'BEGIN {print "TARGET&DESCRIPTION"}\
		{if ($$0 ~ /^##/) {getline target; split(target,a,":");\
		print a[1]"&"substr($$0,4)}}' Makefile | sort | column -t -s '&'

## print a list of profiles
help_profiles:
	sed < Makefile -n -e '1s/^.*/PROFILE\&CFLAGS/p'\
		-e 's/CFLAGS_\([a-z]*\)=\(.*\)/\1\&\2/p' | column -t -s '&'

DOC_ARGS=--viz $(OUT_DIR)/viz --folder $(DOCS_DIR) --debug
## build documentation
docs: build $(OUT_DIR)/viz
	$(PYTHON) scripts/make_docs.py $(DOC_ARGS) $(BBRE_C) internals/AST.md
	$(PYTHON) scripts/make_docs.py $(DOC_ARGS) $(BBRE_C)\
		internals/Charclass_Compiler.md
	$(PYTHON) scripts/make_docs.py $(DOC_ARGS) $(BBRE_H) API.md

## build a folder with bbre + tests for testing on other platforms
port: build $(BBRE_C) $(BBRE_H) test.c test_gen.c mptest.c mptest.h\
		test_config.h
	mkdir -p build/port
	mkdir -p build/port/tools
	cp port/Makefile build/port
	cp -f $(BBRE_C) $(BBRE_H) build/port
	cp -f test.c test_gen.c mptest.c mptest.h test_config.h build/port/tools

## run sanity tests before committing
precommit: test testoom

## show code size statistics
loc: $(BBRE_C) $(BBRE_H)
	wc -l $(BBRE_C) $(BBRE_H)
	echo "$$(cat $(BBRE_C) | tr -dc ';' | wc -c) semicolons."
