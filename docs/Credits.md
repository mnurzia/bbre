# Credits

Most of the techniques used in this library are not original. I would have been unable to write this library if not for the following people, all of whom have contributed ideas:

[Ken Thompson](https://en.wikipedia.org/wiki/Ken_Thompson): Pioneered the [compilation of regular expressions](https://dl.acm.org/doi/10.1145/363347.363387), paving the way for efficient, non-backtracking regular expression algorithms.

[Rob Pike](http://herpolhode.com/rob/): Refined Thompson's algorithm by developing a technique for matching regular expressions using a virtual machine; this technique is used for this library.

[Russ Cox](https://swtch.com/~rsc/): Wrote a hugely influential [series of articles](https://swtch.com/~rsc/regexp/), which served as the theoretical basis for most of this library. Also wrote [re2](https://github.com/google/re2/wiki/Syntax), one of the most widely-used non-backtracking regular expression libraries.

[Philip Hazel](http://quercite.dx.am/): Wrote [PCRE](https://en.wikipedia.org/wiki/Perl_Compatible_Regular_Expressions), arguably the standard for regular expressions. The breadth and utility of this library cannot be overstated. Hazel's advice on testing also resonates: "Effort put into building test harnesses is never wasted."

[Andrew Gallant](https://github.com/BurntSushi): Wrote [Rust's regex crate](https://github.com/rust-lang/regex), which is an excellent library that everyone should use. When writing bbre, I took heavy inspiration from its intuitive API.

[Chris Wellons](https://nullprogram.com/): Wrote the [integer hash function](https://nullprogram.com/blog/2018/07/31/) used in this library. Also, his blog is a great resource for learning about modern idiomatic C.

[Bjoern Hoehrmann](https://bjoern.hoehrmann.de/): Wrote a [DFA-based UTF-8 decoder](https://bjoern.hoehrmann.de/utf-8/decoder/dfa/) which serves as the design basis for the respective component in this library.

[Alexander Pankratov](https://swapped.cc/): Did an [informative writeup](https://github.com/apankrat/notes/blob/master/fast-case-conversion/README.md) on Wine's Unicode casefold array compression algorithm, a derivation of which is used in this library. The [original idea](https://github.com/wine-mirror/wine/commit/a02ce81082ef2f27fdfcf577efbe491582becd28a) seems to have come from [jgriffiths](https://github.com/jgriffiths).

[Simon Tatham](https://www.chiark.greenend.org.uk/~sgtatham/): Invented an [excellent implementation of mergesort](https://www.chiark.greenend.org.uk/~sgtatham/algorithms/listsort.html) for linked lists. This implementation is stable, has guaranteed worst-case performance, and does not require any extra space. In bbre, this algorithm is used to normalize character classes. Tatham is also known for [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/). ([MinTTY](https://github.com/mintty/mintty), a fork of PuTTY, was one of the first terminal emulators I ever used.)

We all stand on the shoulders of giants. I have immense respect for these individuals and their contributions to the field.
