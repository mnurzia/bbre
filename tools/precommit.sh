#!/bin/sh

# This script attempts to exercise all code in this library, including support
# scripts, and builds tests from scratch. It is intended to be run before every
# commit, to ensure that no broken code makes it into the main repository.
# This script is intended to be used for continuous integration.

PROGRAM=$0

STDOUT=$(mktemp)
STDERR=$(mktemp)

step() {
	if [ "$PRECOMMIT_COUNT" = "1" ]; then
		printf "\n"
		return
	fi
	if [ -z "$TOTAL_STEPS" ]; then
		TOTAL_STEPS=$(PRECOMMIT_COUNT=1 $PROGRAM | wc -l)
		CURRENT_STEP=1
	fi
	printf "[%2i/%2i] %s: " "$CURRENT_STEP" "$TOTAL_STEPS" "$1"
	shift
	CURRENT_STEP=$((CURRENT_STEP + 1))
	if "$@" >"$STDOUT" 2>"$STDERR"; then
		echo "OK"
	else
		echo "BAD"
		echo "Stdout:"
		cat "$STDOUT"
		echo "Stderr:"
		cat "$STDERR"
		exit 1
	fi
	if [ "$CURRENT_STEP" = "$((TOTAL_STEPS + 1))" ]; then
		echo "OK"
	fi
}

step "Clean Environment" make clean
step "Build venv" make venv
step "Install venv" . build/venv/bin/activate
step "Update Unicode Tables" make tables
step "Format Sources" make format
step "Check Sources" make check_sources
step "Build Tests" make test_build
step "Run Tests" make test
step "Run OOM Tests" make testoom
step "Run and Check Coverage" make cov_check
step "Run Benchmarks" make PROFILE=bench bench
step "Run Hello World" make port_build
step "Generate Docs" make docs
step "Run fuzzington for 10000000 iterations" make fuzzington_run

exit 0
