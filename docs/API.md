# API Reference
<h2 id="Contents">Contents</h2>
<ul>
<li><a href="#BBRE_ERR_MEM">BBRE_ERR_MEM, BBRE_ERR_PARSE, BBRE_ERR_LIMIT</a></li>
<li><a href="#bbre_alloc_cb">bbre_alloc_cb, bbre_alloc</a></li>
<li><a href="#bbre_flags">bbre_flags</a></li>
<li><a href="#bbre_spec">bbre_spec</a></li>
<li><a href="#bbre_spec_init">bbre_spec_init</a></li>
<li><a href="#bbre">bbre</a></li>
<li><a href="#bbre_init_pattern">bbre_init_pattern</a></li>
<li><a href="#bbre_init">bbre_init</a></li>
<li><a href="#bbre_destroy">bbre_destroy</a></li>
<li><a href="#bbre_get_error">bbre_get_error</a></li>
<li><a href="#bbre_span">bbre_span</a></li>
<li><a href="#bbre_is_match">bbre_is_match, bbre_find, bbre_captures, bbre_which_captures</a></li>
<li><a href="#bbre_is_match_at">bbre_is_match_at, bbre_find_at, bbre_captures_at, bbre_which_captures_at</a></li>
<li><a href="#bbre_capture_count">bbre_capture_count</a></li>
<li><a href="#bbre_capture_name">bbre_capture_name</a></li>
<li><a href="#bbre_set_spec">bbre_set_spec</a></li>
<li><a href="#bbre_set_spec_init">bbre_set_spec_init</a></li>
<li><a href="#bbre_set_spec_destroy">bbre_set_spec_destroy</a></li>
<li><a href="#bbre_set_spec_add">bbre_set_spec_add, bbre_set_spec_config</a></li>
<li><a href="#bbre_set">bbre_set</a></li>
<li><a href="#bbre_set_init_patterns">bbre_set_init_patterns</a></li>
<li><a href="#bbre_set_init">bbre_set_init</a></li>
<li><a href="#bbre_set_destroy">bbre_set_destroy</a></li>
<li><a href="#bbre_set_is_match">bbre_set_is_match, bbre_set_matches</a></li>
<li><a href="#bbre_set_is_match_at">bbre_set_is_match_at, bbre_set_matches_at</a></li>
<li><a href="#bbre_clone">bbre_clone, bbre_set_clone</a></li>
</ul>
<h2 id="BBRE_ERR_MEM"><code>BBRE_ERR_MEM</code>, <code>BBRE_ERR_PARSE</code>, <code>BBRE_ERR_LIMIT</code></h2>
<p>Enumeration of error types.</p>

```c
#define BBRE_ERR_MEM   (-1) /* Out of memory. */
#define BBRE_ERR_PARSE (-2) /* Parsing failed. */
#define BBRE_ERR_LIMIT (-3) /* Hard limit reached (program size, etc.) */
```

<h2 id="bbre_alloc_cb"><code>bbre_alloc_cb</code>, <code>bbre_alloc</code></h2>
<p>Memory allocator callback.</p>

```c
typedef void *(*bbre_alloc_cb)(void *user, void *ptr, size_t prev, size_t next);
typedef struct bbre_alloc {
  void *user;       /* User pointer */
  bbre_alloc_cb cb; /* Allocator callback */
} bbre_alloc;
```
<p>The <a href="#bbre_alloc_cb">bbre_alloc</a> type can be used with most of the bbre_*_init() functions
provided with the library, to define a custom allocator for specific
objects.</p>
<p>To use, set  <code>alloc-&gt;cb</code> to a function with the <a href="#bbre_alloc_cb">bbre_alloc_cb</a> signature, and
optionally set  <code>alloc-&gt;user</code> to a context pointer. The library will pass
<code>alloc-&gt;user</code> to any call of  <code>alloc-&gt;cb</code> that it makes.</p>
<p>The callback itself takes four parameters:</p>
<ul>
<li><code>user</code> is the the pointer in  <code>alloc-&gt;user</code></li>
<li><code>old_ptr</code> is the pointer to the previous allocation (may be NULL)</li>
<li><code>old_size</code> is the size of the previous allocation</li>
<li><code>new_size</code> is the requested size for the next allocation</li>
</ul>
<p>This is a little different from the three-callback option provided by most
libraries. If you are confused, this might help you understand:</p>
<pre><code class="language-c">alloc_cb(user,    NULL,        0, new_size) = malloc(new_size)
alloc_cb(user, old_ptr, old_size, new_size) = realloc(old_ptr, new_size)
alloc_cb(user, old_ptr, old_size,        0) = free(old_ptr)
</code></pre>
<p>This approach was adapted from Lua's memory allocator API.
Of course, the library uses stdlib malloc if possible, so chances are you
don't need to worry about this part of the API.</p>

<h2 id="bbre_flags"><code>bbre_flags</code></h2>
<p>Regular expression flags.</p>

```c
typedef enum bbre_flags {
  BBRE_FLAG_INSENSITIVE = 1, /* (?i) Case insensitive matching */
  BBRE_FLAG_MULTILINE = 2,   /* (?m) Multiline matching */
  BBRE_FLAG_DOTNEWLINE = 4,  /* (?s) '.' matches '\\n' */
  BBRE_FLAG_UNGREEDY = 8     /* (?U) Quantifiers become ungreedy */
} bbre_flags;
```
<p>These mirror the flags used in the regular expression syntax, but can be
given to bbre_spec_flags() in order to enable them out-of-band.</p>

<h2 id="bbre_spec"><code>bbre_spec</code></h2>
<p>Builder class for regular expressions.</p>

```c
typedef struct bbre_spec bbre_spec;
```
<p>This is intended to be used for nontrivial usage of the library, for
example, if you want to use a non-null-terminated regex.</p>

<h2 id="bbre_spec_init"><code>bbre_spec_init</code></h2>
<p>Initialize a <a href="#bbre_spec">bbre_spec</a>.</p>

```c
int bbre_spec_init(
    bbre_spec **pspec, const char *pat, size_t pat_size,
    const bbre_alloc *alloc);
```
<ul>
<li><code>pspec</code> is a pointer to a pointer that will contain the newly-constructed
<a href="#bbre_spec">bbre_spec</a> object.</li>
<li><code>pat</code> is the pattern string to use for the <a href="#bbre_spec">bbre_spec</a> object.</li>
<li><code>pat_size</code> is the size (in bytes) of  <code>pat</code>.</li>
<li><code>alloc</code> is the memory allocator to use. Pass NULL to use the default.</li>
</ul>
<p>Returns BBRE_ERR_NOMEM if there is not enough memory to represent the
object, 0 otherwise. If there was not enough memory,  <code>*pspec</code> is NULL.</p>

<h2 id="bbre"><code>bbre</code></h2>
<p>An object that matches a single regular expression.</p>

```c
typedef struct bbre bbre;
```

<h2 id="bbre_init_pattern"><code>bbre_init_pattern</code></h2>
<p>Initialize a <a href="#bbre">bbre</a>.</p>

```c
bbre *bbre_init_pattern(const char *pat_nt);
```
<p><code>pat_nt</code> is a null-terminated string containing the pattern.</p>
<p>Returns a newly-constructed <a href="#bbre">bbre</a> object, or NULL if there was not enough
memory to store the object. Internally, this function calls
<a href="#bbre_init">bbre_init</a>(), which can return more than one error code if the pattern is
malformed: this function assumes the pattern is correct and will abort if
these errors occur. If you require more robust error checking, use
<a href="#bbre_init">bbre_init</a>() directly.</p>

<h2 id="bbre_init"><code>bbre_init</code></h2>
<p>Initialize a <a href="#bbre">bbre</a> from a <a href="#bbre_spec">bbre_spec</a>.</p>

```c
int bbre_init(bbre **preg, const bbre_spec *spec, const bbre_alloc *alloc);
```
<ul>
<li><code>preg</code> is a pointer to a pointer that will contain the newly-constucted
<a href="#bbre">bbre</a> object.</li>
<li><code>spec</code> is a <a href="#bbre_spec">bbre_spec</a> used for initializing the  <code>*preg</code>.</li>
<li><code>alloc</code> is the memory allocator to use. Pass NULL to use the default.</li>
</ul>
<p>Returns <a href="#BBRE_ERR_MEM">BBRE_ERR_PARSE</a> if the pattern in  <code>spec</code> contains a parsing error,
<a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to parse or compile the
pattern, <a href="#BBRE_ERR_MEM">BBRE_ERR_LIMIT</a> if the pattern's compiled size is too large, or 0
if there was no error.
If this function returns <a href="#BBRE_ERR_MEM">BBRE_ERR_PARSE</a>, you can use the <a href="#bbre_get_error">bbre_get_error</a>()
function to retrieve a detailed error message, and an index into the pattern
where the error occurred.</p>

<h2 id="bbre_destroy"><code>bbre_destroy</code></h2>
<p>Destroy a <a href="#bbre">bbre</a>.</p>

```c
void bbre_destroy(bbre *reg);
```

<h2 id="bbre_get_error"><code>bbre_get_error</code></h2>
<p>Retrieve a parsing error from a \ref <a href="#bbre">bbre</a>.</p>

```c
size_t bbre_get_error(bbre *reg, const char **pmsg, size_t *pos);
```
<ul>
<li><code>reg</code> is the <a href="#bbre">bbre</a> to check the error of.</li>
<li><code>pmsg</code> is a pointer to the output message.  <code>*pmsg</code> will be set to the
error message.  <code>*pmsg</code> is always null-terminated if an error occurred.</li>
<li><code>ppos</code> is a pointer to the output position.  <code>*ppos</code> will be set to
the index in the input pattern where the error occurred.</li>
</ul>
<p>Returns the length (in bytes) of  <code>*pmsg</code>, not including its null terminator.
If the preceding call to <a href="#bbre_init">bbre_init</a>() did not cause a parse error (i.e., it
did not return <a href="#BBRE_ERR_MEM">BBRE_ERR_PARSE</a>) then  <code>*pmsg</code> is NULL,  <code>*ppos</code> is 0, and the
function returns 0.</p>

<h2 id="bbre_span"><code>bbre_span</code></h2>
<p>Substring bounds record.</p>

```c
typedef struct bbre_span {
  size_t begin; /* Begin index */
  size_t end;   /* End index */
} bbre_span;
```
<p>This structure records the bounds of a capture recorded by <a href="#bbre_is_match">bbre_captures</a>().
<code>begin</code> is the start of the match,  <code>end</code> is the end.</p>

<h2 id="bbre_is_match"><code>bbre_is_match</code>, <code>bbre_find</code>, <code>bbre_captures</code>, <code>bbre_which_captures</code></h2>
<p>Match text against a <a href="#bbre">bbre</a>.</p>

```c
int bbre_is_match(bbre *reg, const char *text, size_t text_size);
int bbre_find(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_bounds);
int bbre_captures(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_captures,
    unsigned int out_captures_size);
int bbre_which_captures(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_captures,
    unsigned int *out_captures_did_match, unsigned int out_captures_size);
```
<p>These functions perform matching operations using a <a href="#bbre">bbre</a> object. All of them
take two parameters,  <code>text</code> and  <code>text_size</code>, which denote the string to
match against.</p>
<p><a href="#bbre_is_match">bbre_is_match</a>() checks if  <code>reg</code>'s pattern occurs anywhere within  <code>text</code>.
Like the rest of these functions, <a href="#bbre_is_match">bbre_is_match</a>() returns 0 if the pattern
did not match anywhere in the string, or 1 if it did.</p>
<p><a href="#bbre_is_match">bbre_find</a>() locates the position in  <code>text</code> where  <code>reg</code>'s pattern occurs, if
it occurs.  <code>out_bounds</code> points to a <a href="#bbre_span">bbre_span</a> where the boundaries of the
match will be stored should a match be found.</p>
<p><a href="#bbre_is_match">bbre_captures</a>() works like <a href="#bbre_is_match">bbre_find</a>(), but it also extracts capturing
groups.  <code>out_captures_size</code> is the amount of groups to capture, and
<code>out_captures</code> points to an array of <a href="#bbre_span">bbre_span</a> where the boundaries of each
capture will be stored. Note that capture group 0 denotes the boundaries of
the entire match (i.e., those retrieved by <a href="#bbre_is_match">bbre_find</a>()), so to retrieve the
first capturing group, pass 2 for  <code>out_captures_size</code>; to retrieve the
second, pass 3, and so on.</p>
<p>Finally, <a href="#bbre_is_match">bbre_which_captures</a>() works like <a href="#bbre_is_match">bbre_captures</a>(), but accepts an
additional argument  <code>out_captures_did_match</code> that points to an array of
<code>out_captures_size</code> integers. Element  <code>n</code> of  <code>out_captures_did_match</code> will
be set to 1 if capture group  <code>n</code> appeared in the match, and 0 otherwise.
Like <a href="#bbre_is_match">bbre_captures</a>(), there is an implicit 0th group that represents the
bounds of the entire match. Consequently,  <code>out_captures_did_match[0]</code> will
always be set to 1, assuming  <code>out_captures_size &gt;= 1</code>. This function is
only useful when a particular pattern can match one but not another group,
such as the pattern  <code>(a)|(b)</code>.</p>
<p>All functions return 0 if a match was not found anywhere in  <code>text</code>, 1 if a
match was found, in which case the relevant  <code>out_bounds</code>,  <code>out_captures</code>,
and/or  <code>out_captures_did_match</code> variable(s) will be written to, or
<a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to successfully perform the
match.</p>

<h2 id="bbre_is_match_at"><code>bbre_is_match_at</code>, <code>bbre_find_at</code>, <code>bbre_captures_at</code>, <code>bbre_which_captures_at</code></h2>
<p>Match text against a <a href="#bbre">bbre</a>, starting the match from a given position.</p>

```c
int bbre_is_match_at(bbre *reg, const char *text, size_t text_size, size_t pos);
int bbre_find_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_bounds);
int bbre_captures_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_captures, unsigned int out_captures_size);
int bbre_which_captures_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_captures, unsigned int *out_captures_did_match,
    unsigned int out_captures_size);
```
<p>These functions behave identically to the <a href="#bbre_is_match">bbre_is_match</a>(), <a href="#bbre_is_match">bbre_find</a>(),
<a href="#bbre_is_match">bbre_captures</a>(), and <a href="#bbre_is_match_at">bbre_captures_at</a>() functions, but they take an
additional  <code>pos</code> parameter that describes an offset in  <code>text</code> to start the
match from.</p>
<p>The utility of these functions is that they take into account empty-width
assertions active at  <code>pos</code>. For example, matching  <code>\b</code> against &quot;A &quot; at
position 1 would return a match, because these functions look at the
surrounding characters for empty-width assertion context.</p>

<h2 id="bbre_capture_count"><code>bbre_capture_count</code></h2>
<p>Get the number of capture groups in the given regex.</p>

```c
unsigned int bbre_capture_count(const bbre *reg);
```
<p>This will always return 1 or more.</p>

<h2 id="bbre_capture_name"><code>bbre_capture_name</code></h2>
<p>Get the name of the given capture group index.</p>

```c
const char *bbre_capture_name(
    const bbre *reg, unsigned int capture_idx, size_t *out_name_size);
```
<p>Returns a constant null-terminated string with the capture group name. For
capture group 0, returns the empty string &quot;&quot;, and for any capture group with
<code>capture_idx &gt;= bbre_capture_count(reg)</code>, returns NULL.
<code>capture_idx</code> is the index of the capture group, and  <code>out_name_size</code> points
to a  <code>size_t</code> that will hold the length (in bytes) of the return value.
<code>out_name_size</code> may be NULL, in which case the length is not written.
The return value of this function, if non-NULL, is guaranteed to be
null-terminated.</p>

<h2 id="bbre_set_spec"><code>bbre_set_spec</code></h2>
<p>Builder class for regular expression sets.</p>

```c
typedef struct bbre_set_spec bbre_set_spec;
```

<h2 id="bbre_set_spec_init"><code>bbre_set_spec_init</code></h2>
<p>Initialize a <a href="#bbre_set_spec">bbre_set_spec</a>.</p>

```c
int bbre_set_spec_init(bbre_set_spec **pspec, const bbre_alloc *alloc);
```
<ul>
<li><code>pspec</code> is a pointer to a pointer that will contain the newly-constructed
<a href="#bbre_set_spec">bbre_set_spec</a> object.</li>
<li><code>alloc</code> is the <a href="#bbre_alloc_cb">bbre_alloc</a> memory allocator to use. Pass NULL to use the
default.</li>
</ul>
<p>Returns <a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to store the object,
0 otherwise.</p>

<h2 id="bbre_set_spec_destroy"><code>bbre_set_spec_destroy</code></h2>
<p>Destroy a <a href="#bbre_set_spec">bbre_set_spec</a>.</p>

```c
void bbre_set_spec_destroy(bbre_set_spec *b);
```

<h2 id="bbre_set_spec_add"><code>bbre_set_spec_add</code>, <code>bbre_set_spec_config</code></h2>
<p>Add a pattern to a <a href="#bbre_set_spec">bbre_set_spec</a>.</p>

```c
int bbre_set_spec_add(bbre_set_spec *set, const bbre *reg);
int bbre_set_spec_config(bbre_set_spec *b, int option, ...);
```
<ul>
<li><code>set</code> is the set to add the pattern to</li>
<li><code>reg</code> is the pattern to add</li>
</ul>
<p>Returns <a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to add  <code>reg</code> to  <code>set</code>,
0 otherwise.</p>

<h2 id="bbre_set"><code>bbre_set</code></h2>
<p>An object that concurrently matches sets of regular expressions.</p>

```c
typedef struct bbre_set bbre_set;
```
<p>A <a href="#bbre_set">bbre_set</a> is not able to extract bounds or capture information about its
individual patterns, but it can match many patterns at once very efficiently
and compute which pattern(s) match a given text.</p>

<h2 id="bbre_set_init_patterns"><code>bbre_set_init_patterns</code></h2>
<p>Initialize a <a href="#bbre_set">bbre_set</a>.</p>

```c
bbre_set *bbre_set_init_patterns(const char *const *ppats_nt, size_t num_pats);
```
<ul>
<li><code>ppats_nt</code> is an array of null-terminated patterns to initialize the
set with.</li>
<li><code>num_pats</code> is the number of patterns in  <code>pats_nt</code>.</li>
</ul>
<p>Returns a newly-constructed <a href="#bbre_set">bbre_set</a> object, or NULL if there was not enough
memory to store the object. Internally, this function calls
<a href="#bbre_set_init">bbre_set_init</a>(), which can return more than one error code: this function
assumes that input patterns are correct and will abort if these errors occur
If you require more robust error checking, use <a href="#bbre_set_init">bbre_set_init</a>() directly.</p>

<h2 id="bbre_set_init"><code>bbre_set_init</code></h2>
<p>Initialize a <a href="#bbre_set">bbre_set</a> from a <a href="#bbre_set_spec">bbre_set_spec</a>.</p>

```c
int bbre_set_init(
    bbre_set **pset, const bbre_set_spec *set_spec, const bbre_alloc *alloc);
```
<ul>
<li><code>pset</code> is a pointer to a pointer that will contain the newly-constructed
<a href="#bbre_set_spec">bbre_set_spec</a> object.</li>
<li><code>set_spec</code> is the <a href="#bbre_set_spec">bbre_set_spec</a> to initialize this object with.</li>
<li><code>alloc</code> is the <a href="#bbre_alloc_cb">bbre_alloc</a> memory allocator to use. Pass NULL to use the
default.</li>
</ul>
<p>Returns <a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to construct the object,
0 otherwise.</p>

<h2 id="bbre_set_destroy"><code>bbre_set_destroy</code></h2>
<p>Destroy a <a href="#bbre_set">bbre_set</a>.</p>

```c
void bbre_set_destroy(bbre_set *set);
```

<h2 id="bbre_set_is_match"><code>bbre_set_is_match</code>, <code>bbre_set_matches</code></h2>
<p>Match text against a <a href="#bbre_set">bbre_set</a>.</p>

```c
int bbre_set_is_match(bbre_set *set, const char *text, size_t text_size);
int bbre_set_matches(
    bbre_set *set, const char *text, size_t text_size, unsigned int *out_idxs,
    unsigned int out_idxs_size, unsigned int *out_num_idxs);
```
<p>These functions perform multi-matching of patterns. They both take two
parameters,  <code>text</code> and  <code>text_size</code>, which denote the string to match
against.</p>
<p><a href="#bbre_set_is_match">bbre_set_is_match</a>() simply checks if any of the individual patterns in  <code>set</code>
match within  <code>text</code>, returning 1 if so and 0 if not.</p>
<p><a href="#bbre_set_is_match">bbre_set_matches</a>() checks which patterns in  <code>set</code> matched within  <code>text</code>.</p>
<ul>
<li><code>out_idxs</code> is a pointer to an array that will hold the indices of the
patterns found in  <code>text</code>.</li>
<li><code>out_idxs_size</code> is the maximum number of indices able to be written to
<code>out_idxs</code>.</li>
<li><code>out_num_idxs</code> is a pointer to an integer that will hold the number of
indices written to  <code>out_idxs</code>.</li>
</ul>
<p>Returns 1 if any pattern in  <code>set</code> matched within  <code>text</code>, 0 if not, or
<a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to perform the match.</p>

<h2 id="bbre_set_is_match_at"><code>bbre_set_is_match_at</code>, <code>bbre_set_matches_at</code></h2>
<p>Match text against a <a href="#bbre_set">bbre_set</a>, starting the match from a given position.</p>

```c
int bbre_set_is_match_at(
    bbre_set *set, const char *text, size_t text_size, size_t pos);
int bbre_set_matches_at(
    bbre_set *set, const char *text, size_t text_size, size_t pos,
    unsigned int *out_idxs, unsigned int out_idxs_size,
    unsigned int *out_num_idxs);
```
<p>These functions perform identically to the <a href="#bbre_set_is_match">bbre_set_is_match</a>() and
<a href="#bbre_set_is_match">bbre_set_matches</a>() functions, except they take an additional  <code>pos</code> argument
that denotes where to start matching from.</p>
<p>See <a href="#bbre_is_match_at">bbre_is_match_at</a>() and its related functions for an explanation as to
why these functions are needed.</p>

<h2 id="bbre_clone"><code>bbre_clone</code>, <code>bbre_set_clone</code></h2>
<p>Duplicate a <a href="#bbre">bbre</a> or <a href="#bbre_set">bbre_set</a> without recompiling it.</p>

```c
int bbre_clone(bbre **pout, const bbre *reg, const bbre_alloc *alloc);
int bbre_set_clone(
    bbre_set **pout, const bbre_set *set, const bbre_alloc *alloc);
```
<p>If you want to match a pattern using multiple threads, you will need to call
this function once per thread to obtain exclusive <a href="#bbre">bbre</a>/<a href="#bbre_set">bbre_set</a> objects to
use, as <a href="#bbre">bbre</a> and <a href="#bbre_set">bbre_set</a> objects cannot be used concurrently.</p>
<p>In a future update, these functions may become no-ops.</p>
<p>Returns <a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to clone the object, 0
otherwise.</p>

