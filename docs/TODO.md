# TODO

Below is a list of features that I'd like `bbre` to support, but either don't have time for or find too difficult.
- Unicode word boundaries
- Mechanized testing of empty-width assertions in the fuzzington
- Intelligent multithreading support (rather than copying the regex for every thread)
    - I am hesitant to add this, as it would require adding pluggable thread api support, for not much of a benefit (I am skeptical about the performance benefits of a shared DFA cache, and they are complicated and difficult to implement in C)
- Less fraggy memory allocations: under the hood, `bbre` objects are a bunch of big-ass vectors that get reallocated a lot; not great for embedded applications
- ICU character class support (maybe just tighten up ICU regex support thoroughly)
- Decouple from or fix up the [`mptest`](https://github.com/mnurzia/mptest) library. I wrote this library in my freshman year of college, which was when I started getting serious about testing my C code. This library has lots of features but requires an antequated external build system that needs to be dropped before I stop feeling embarrassed about testing `bbre` with it.
- Testing against other regexp libraries for consistency (want at least: re2, rust-regex)
