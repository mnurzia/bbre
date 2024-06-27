# Credits

Most of the techniques used in this library are not original. I would have been unable to write this library if not for the following people, all of whom have contributed ideas:

[Ken Thompson](https://en.wikipedia.org/wiki/Ken_Thompson): Pioneered the [compilation of regular expressions](https://dl.acm.org/doi/10.1145/363347.363387), paving the way for efficient, non-backtracking regular expression algorithms.

[Rob Pike](http://herpolhode.com/rob/): Refined Thompson's algorithm by developing a technique for matching regular expressions using a virtual machine; this technique is used for this library.

[Russ Cox](https://swtch.com/~rsc/): Wrote a hugely influential [series of articles](https://swtch.com/~rsc/regexp/), which served as the theoretical basis for most of this library. Also wrote [re2](https://github.com/google/re2/wiki/Syntax), one of the most widely-used non-backtracking regular expression libraries.

[Philip Hazel](https://en.wikipedia.org/wiki/Philip_Hazel): Wrote [PCRE](https://en.wikipedia.org/wiki/Perl_Compatible_Regular_Expressions), arguably the standard for regular expressions. The breadth and utility of this library cannot be overstated.

[Andrew Gallant](https://github.com/BurntSushi): Wrote [Rust's regex crate](https://github.com/rust-lang/regex), which is an excellent library that everyone should use. When writing bbre, I took heavy inspiration from its intuitive API.

We all stand on the shoulders of giants. I have immense respect for these individuals and their contributions to the field.
