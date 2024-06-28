# Testing

bbre is heavily tested.

A set of basic tests in `tools/test.c` provides XXX% coverage and defines the general behavior of the library. These tests are intended to be mostly readable and exercise all library features.

These tests are also instrumented with a harness that simulates out-of-memory conditions and ensures that the code behaves correctly under them. 

Additionally, the `tools/test_gen.c` file contains automatically generated tests that cover testing of large, tedious sets of inputs such as Unicode properties. These tests ensure, among other things, that `bbre` adheres to the Unicode standard.

The `tools/fuzzington` test harness, written in Rust, is a fuzzer that generates hundreds of thousands of regular expressions per second and matches them against generated text. This test harness has already caught dozens of bugs.

`tools/parser_fuzz.c` is a test harness for [libFuzzer](https://llvm.org/docs/LibFuzzer.html). This has also caught many bugs already.

`tools/test_gen.c` also contains regression tests for all bugs found through fuzzing. Several harness scripts in the `tools/` directory run the available fuzzers, and then automatically write and import test code once an anomaly is detected.
