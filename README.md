# bbre

Regular expression engine written in ANSI C.

Features:
- Non-backtracking (linear-time execution guarantee)
- One `.h` file and one `.c` file
- Supports matching many distinct patterns at once (regexp sets)
- Syntax parity with [re2](https://github.com/google/re2/wiki/Syntax)
- ~6000 lines of code (only ~1800 semicolons)
- Extensively tested
- Pluggable allocator support

| [API](docs/API.md) | [Syntax](docs/Syntax.md) | [Testing](docs/Testing.md) | [Goals](docs/Goals.md) | [Credits](docs/Credits.md) | [TODO](docs/TODO.md) |
| ------------------ | ------------------------ | -------------------------- | ---------------------- | -------------------------- | -------------------- |

## Usage

```c
#include <assert.h>
#include <string.h>

#include "bbre.h"

int main(void)
{
  const char *text = "Hello WorLd!";
  bbre *reg = bbre_init_pattern("Hel*o (?i)[w]orld!");
  assert(bbre_is_match(reg, text, strlen(text)) == 1);
  bbre_destroy(reg);
  return 0;
}
```

## FAQ

### Why write this?

I like regular expressions and C89.

### You should have written this in Rust.

That would have been too much fun.

### What does the `bb` stand for?

"blueberry", because I ate a lot of frozen blueberries while I wrote this.

## Caveats

- Written in C89.
- Not optimized for memory fragmentation: uses lots of variable-size buffers.
- Assumes width of integer types in a way that's not completely compliant with C89/99. This works on 99% of platforms out there, but of course part of the fun in C is the esoteric 1%.
- Probably won't work on EBCDIC systems.

