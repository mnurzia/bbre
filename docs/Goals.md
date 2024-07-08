# Goals

bbre's list of design goals (in rough order of priority) are:

<ol start="0">
<li>

*Correctness*: In this case, correctness means behaving exactly as the library is specced to behave. For bbre, this means adhering to the [Syntax](Syntax.md) and [API](API.md) descriptions, which are both in turn grounded in the conventions laid out by other regex libraries. This is #0 because it's not exactly a goal since it's so obvious. Any regex library worth its salt should strive to be correct and predictable in its usage.

</li>
<li>

*Safety*: Deep down, I, as the author of this library, know that bbre is inherently unsafe, solely because it is written in C. However, we should try as hard as possible, through aggressive testing/fuzzing, to expose and correct safety issues. Additionally, the API and design of the code should minimize the potential for safety issues. See [Testing](Testing.md) for more philosophy about this. Part of being safe is providing complexity guarantees too: untrusted inputs to bbre only influence linear or logarithmic algorithms.

</li>
<li>

*Simplicity*: This goes hand in hand with Safety and many of the other points in this list. In C, more so than other languages, simplicity is a virtue: at least for me, the more C code I have, the worse my C code is. Cutting down on code makes it accessible to other developers, and makes it more auditable/hackable.

</li>
<li>

*Ease of Use/Portability*: C libraries (especially those with complicated build processes or lots of translation units) can be hard to integrate into larger projects. bbre expressly chooses a conservative C standard and zero dependencies (beyond a few freestanding functions in libc like `memcpy` and `strlen`) in order to facilitate easy usage. Also, bbre will always be distributed as a single .c/.h pair.

</li>
<li>

*Speed*: Finally, the library should be reasonably fast, without sacrificing the above goals in an unreasonable way. This sounds like a canned lawyer response, but I'm just trying to be nuanced, speed (especially in C) is typically about tradeoffs.

</li>
</ol>
