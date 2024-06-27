#!/bin/sh
# Run soak tests, fuzzington, and benchmarks.
# Soak it up!
PROGRAM=$0

STDOUT=$(mktemp)
STDERR=$(mktemp)

step() {
  if [ "$CAR_SHAKER_COUNT" = "1" ]; then
    printf "\n"
    return
  fi
  if [ -z "$TOTAL_STEPS" ]; then
    TOTAL_STEPS=$(CAR_SHAKER_COUNT=1 $PROGRAM | wc -l)
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
    echo "Soaked! Commit commit commit!"
  fi
}

step "Clean Environment" make clean
step "Update Unicode Tables" make tables
step "Format Sources" make format
step "Check Sources" make check_sources
step "Build Tests" make test_build
step "Run Tests" make test
step "Run OOM Tests" make testoom
# step "Run and Check Coverage" make check_cov
step "Run Hello World" make port_build
step "Generate Docs" make docs
step "Run fuzzington for 10000000 iterations" make fuzzington_run

exit 0
