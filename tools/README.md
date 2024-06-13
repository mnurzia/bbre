# `tools`

This directory contains tools for developing `bbre`.

- `scripts/`: Python scripts used for generating code, tests, and documentation.
- `port/`: skeleton for building a minimal distribution of `bbre` and its tests that can be used for porting to different platforms without, for example, Python or a `gcc`-compatible C compiler.
- `fuzzington/`: a regex fuzzer written in Rust that is used to fuzz `bbre`.
