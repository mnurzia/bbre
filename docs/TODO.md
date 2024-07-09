# TODO

Below is a list of features that I'd like `bbre` to support, but either don't have time for or find too difficult.
- Unicode word boundaries
- Mechanized testing of empty-width assertions
- Intelligent multithreading support (rather than copying the regex for every thread)
    - I am hesitant to add this, as it would require adding pluggable thread api support, for not much of a benefit (I am skeptical about the performance benefits of a shared DFA cache)
- Less fraggy memory allocations: under the hood, `bbre` objects are a bunch of big-ass vectors that get reallocated a lot; not great for embedded applications
- ICU character class resort (maybe just tighten up ICU regex support)
