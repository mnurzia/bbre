# Testing

bbre is heavily tested, but it can always use more testing.

A set of basic tests in `tools/test.c` provides 100% coverage (both line and branch) and defines the general behavior of the library. These tests are intended to be readable by humans and exercise all library features.

*A note about that 100% number:* 100% coverage is not a silver bullet; but in my experience it seriously reduced the amount of logic bugs I had to contend with while writing a piece of complex software in C. Getting to 100% coverage implies removing all dead code, and removing all dead code implies having a much deeper understanding of the invariants of your algorithms. This kind of coverage testing does not protect you from more fundamental, semantical disconnects in the developer's brain, it just proves that their code (probably) does what they want it to.

These tests are also instrumented by using a harness that simulates out-of-memory conditions. This ensures that the code behaves correctly under such rare yet possible conditions.

Additionally, the `tools/test_gen.c` file contains automatically generated tests that cover testing of large, tedious sets of inputs such as Unicode properties. These tests ensure, among other things, that `bbre` adheres to the parts of the Unicode standard that it claims to adhere to.

The `tools/fuzzington` test harness, written in Rust, is a fuzzer that generates hundreds of thousands of regular expressions per second and matches them against generated text. This test harness has already caught dozens of bugs.

`tools/parser_fuzz.c` is a test harness for [libFuzzer](https://llvm.org/docs/LibFuzzer.html). This has also caught many bugs already.

`tools/test_gen.c` also contains regression tests for all bugs found through fuzzing. Several harness scripts in the `tools/` directory run the available fuzzers, and then automatically write and import test code once an anomaly is detected.
