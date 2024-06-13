# bbre

Regular expression engine written in ANSI C.

Features:
- Non-backtracking (linear-time execution guarantee)
- One `.h` file and one `.c` file
- Supports matching many distinct patterns at once
- Syntax parity with [re2](https://github.com/google/re2/wiki/Syntax)
- ~5000 lines of code (only ~1500 semicolons)
- Extensively tested (XXX.XX% line / branch coverage)
- Pluggable allocator support

## FAQ

### Why?

I like regular expressions and C89.

### You should have written this in Rust.

That would have been too easy.

### What does the `bb` stand for?

"blueberry", because I ate a lot of frozen blueberries while I wrote this. But you can choose to read it in any way you like -- "big booty", "bagel bite", "barnacle boy", and "bikini bottom" are all valid interpretations.

## Caveats
- Written in C89.
- Not optimized for memory fragmentation: uses lots of variable-size buffers.
- Assumes width of integer types in a way that's not completely compliant with C89/99. This works on 99% of platforms out there, but of course part of the fun in C is catering to the esoteric 1%.
- Written in C90.

