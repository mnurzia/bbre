# Credits

Most of the techniques used in this library are not original. I would have been unable to write this library if not for the following people, all of whom have contributed ideas, either personally or through broader contributions to the field:

[Ken Thompson](https://en.wikipedia.org/wiki/Ken_Thompson): Pioneered the [compilation of regular expressions](https://dl.acm.org/doi/10.1145/363347.363387), paving the way for efficient, non-backtracking regular expression algorithms.

[Rob Pike](http://herpolhode.com/rob/): Refined Thompson's algorithm by developing a technique for matching regular expressions using a virtual machine; that technique is used in this library.

[Russ Cox](https://swtch.com/~rsc/): Wrote a hugely influential [series of articles](https://swtch.com/~rsc/regexp/), which served as the theoretical basis for most of this library. Also wrote [re2](https://github.com/google/re2/wiki/Syntax), one of the most widely-used non-backtracking regular expression libraries.

[Philip Hazel](http://quercite.dx.am/): Wrote [PCRE](https://en.wikipedia.org/wiki/Perl_Compatible_Regular_Expressions), arguably the standard for regular expressions. The breadth and utility of this library cannot be overstated. Hazel's advice on testing also resonates: "Effort put into building test harnesses is never wasted."

[Andrew Gallant](https://github.com/BurntSushi): Wrote [Rust's regex crate](https://github.com/rust-lang/regex), which is an excellent library that everyone should use, if they can. When writing bbre, I took heavy inspiration from its intuitive API.

[Chris Wellons](https://nullprogram.com/): Wrote the [integer hash function](https://nullprogram.com/blog/2018/07/31/) used in this library. Also, his blog is a great resource for learning about modern idiomatic C.

[Bjoern Hoehrmann](https://bjoern.hoehrmann.de/): Wrote a [DFA-based UTF-8 decoder](https://bjoern.hoehrmann.de/utf-8/decoder/dfa/) which serves as the design basis for the respective component in this library.

[Alexander Pankratov](https://swapped.cc/): Did an [informative writeup](https://github.com/apankrat/notes/blob/master/fast-case-conversion/README.md) on Wine's Unicode casefold array compression algorithm, a derivation of which is used in this library. The [original idea](https://github.com/wine-mirror/wine/commit/a02ce81082ef2f27fdfcf577efbe491582becd28a) seems to have come from [Jon Griffiths](https://github.com/jgriffiths).

[Simon Tatham](https://www.chiark.greenend.org.uk/~sgtatham/): Invented an [excellent implementation of mergesort](https://www.chiark.greenend.org.uk/~sgtatham/algorithms/listsort.html) for linked lists. This implementation is stable, has guaranteed worst-case performance, and does not require any extra space. In bbre, this algorithm is used to normalize character classes. Tatham is also known for [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/). ([MinTTY](https://github.com/mintty/mintty), a fork of PuTTY, was one of the first terminal emulators I ever used.)

[D. Richard Hipp](https://www.hwaci.com/index.html): Wrote [SQLite](https://sqlite.org/), the ubiquitous database engine. SQLite's design strategy and documentation are full of great techniques for writing robust and vigorously tested C programs. Of important note is SQLite's [testing methodology](https://sqlite.org/testing.html), which I've replicated a small portion of in this library to great success. Applying a combination of coverage and fuzz testing allowed me to catch many bugs early on.

[Sid Mane](https://github.com/squidscode): Reviewed the code in this library and offered valuable feedback on the design of the API. Sid is a personal friend and a fellow student at Northeastern. I owe Sid a streaming match API, and haven't forgotten about it.

[Joe Allen](https://github.com/jhallen): Reviewed and tested this library, as well as giving great advice and conversation about the design of regular expression engines. Joe is the original author of [Joe's Own Editor](https://github.com/jhallen/joe-editor), and also a former colleague that I had the fortune of working with at one of my internships.

Every software developer stands on the shoulders of giants. I have immense respect for these individuals and their contributions.

I (Max Nurzia) originally wrote this program throughout 2024, during my third year at Northeastern University in Boston, MA. During my first year of college, I wrote [another regular expression library](https://github.com/mnurzia/re). This library had numerous inherent issues and was never fully finished, but many of the ideas contained in it were carried over to bbre.
