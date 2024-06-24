# API Reference
<h2 id="Contents">Contents</h2>
<ul>
<li><a href="#BBRE_ERR_MEM">BBRE_ERR_MEM, BBRE_ERR_PARSE, BBRE_ERR_LIMIT</a></li>
<li><a href="#bbre_alloc_cb">bbre_alloc_cb, bbre_alloc</a></li>
<li><a href="#bbre_flags">bbre_flags</a></li>
<li><a href="#bbre_spec">bbre_spec</a></li>
<li><a href="#bbre_spec_init">bbre_spec_init</a></li>
<li><a href="#bbre">bbre</a></li>
<li><a href="#bbre_init">bbre_init</a></li>
<li><a href="#bbre_init_spec">bbre_init_spec</a></li>
<li><a href="#bbre_destroy">bbre_destroy</a></li>
<li><a href="#bbre_get_error">bbre_get_error</a></li>
<li><a href="#bbre_span">bbre_span</a></li>
<li><a href="#bbre_is_match">bbre_is_match, bbre_find, bbre_captures</a></li>
<li><a href="#bbre_is_match_at">bbre_is_match_at, bbre_find_at, bbre_captures_at</a></li>
<li><a href="#bbre_set_spec">bbre_set_spec</a></li>
<li><a href="#bbre_set_spec_init">bbre_set_spec_init</a></li>
<li><a href="#bbre_set_spec_destroy">bbre_set_spec_destroy</a></li>
<li><a href="#bbre_set_spec_add">bbre_set_spec_add, bbre_set_spec_config, bbre_set, bbre_set_init, bbre_set_init_spec, bbre_set_destroy, bbre_set_match</a></li>
<li><a href="#bbre_fork">bbre_fork, bbre_set_fork</a></li>
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
  void *user;
  bbre_alloc_cb cb;
} bbre_alloc;
```
<p>This is a little different from the three-callback option provided by most
libraries. If you are confused, this might help you understand:</p>
<pre><code class="language-c">alloc_cb(user,    NULL,        0, new_size) = malloc(new_size)
alloc_cb(user, old_ptr, old_size, new_size) = realloc(old_ptr, new_size)
alloc_cb(user, old_ptr, old_size,        0) = free(old_ptr)
</code></pre>
<p>Of course, the library uses stdlib malloc if possible, so chances are you
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
    bbre_spec **pspec, const char *pat, size_t pat_size, bbre_alloc_cb alloc);
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

<h2 id="bbre_init"><code>bbre_init</code></h2>
<p>Initialize a <a href="#bbre">bbre</a>.</p>

```c
bbre *bbre_init(const char *pat_nt);
```
<p><code>pat_nt</code> is a null-terminated string containing the pattern.</p>
<p>Returns a newly-constructed <a href="#bbre">bbre</a> object, or NULL if there was not enough
memory to store the object. Internally, this function calls
<a href="#bbre_init_spec">bbre_init_spec</a>(), which can return more than one error code if the pattern
is malformed: this function assumes the pattern is correct and will abort
if these errors occur. If you require more robust error checking, use
<a href="#bbre_init_spec">bbre_init_spec</a>() directly.</p>

<h2 id="bbre_init_spec"><code>bbre_init_spec</code></h2>
<p>Initialize a <a href="#bbre">bbre</a> from a <a href="#bbre_spec">bbre_spec</a>.</p>

```c
int bbre_init_spec(bbre **preg, const bbre_spec *spec, bbre_alloc alloc);
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

<h2 id="bbre_is_match"><code>bbre_is_match</code>, <code>bbre_find</code>, <code>bbre_captures</code></h2>
<p>Match text against a <a href="#bbre">bbre</a>.</p>

```c
int bbre_is_match(bbre *reg, const char *text, size_t text_size);
int bbre_find(
    bbre *reg, const char *text, size_t text_size, bbre_span *out_bounds);
int bbre_captures(
    bbre *reg, const char *text, size_t text_size, bbre_u32 num_captures,
    bbre_span *out_captures);
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
groups.  <code>num_captures</code> is the amount of groups to capture, and
<code>out_captures</code> points to an array of <a href="#bbre_span">bbre_span</a> where the boundaries of each
capture will be stored. Note that capture group 0 denotes the boundaries of
the entire match (i.e., those retrieved by <a href="#bbre_is_match">bbre_find</a>()), so to retrieve the
first capturing group, pass 2 for  <code>num_captures</code>; to retrieve the second,
pass 3, and so on.</p>
<p>Returns 0 if a match was not found anywhere in  <code>text</code>, 1 if a match was
found, in which case the relevant  <code>out_bounds</code> or  <code>out_captures</code> variable
will be written to, or <a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to
successfully perform the match.</p>

<h2 id="bbre_is_match_at"><code>bbre_is_match_at</code>, <code>bbre_find_at</code>, <code>bbre_captures_at</code></h2>
<p>Match text against a <a href="#bbre">bbre</a>, starting the match from a given position.</p>

```c
int bbre_is_match_at(bbre *reg, const char *text, size_t text_size, size_t pos);
int bbre_find_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_bounds);
int bbre_captures_at(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_u32 num_captures, bbre_span *out_captures);
```
<p>These functions behave identically to the <a href="#bbre_is_match">bbre_is_match</a>(), <a href="#bbre_is_match">bbre_find</a>(), and
<a href="#bbre_is_match">bbre_captures</a>() functions, but they take an additional  <code>pos</code> parameter that
describes an offset in  <code>text</code> to start the match from.
The utility of these functions is that they take into account empty-width
assertions active at  <code>pos</code>. For example, matching  <code>\b</code> against &quot;A &quot; at
position 1 would return a match, because these functions look at the
surrounding characters for empty-width assertion context.</p>

<h2 id="bbre_set_spec"><code>bbre_set_spec</code></h2>
<p>Builder class for regular expression sets.</p>

```c
typedef struct bbre_set_spec bbre_set_spec;
```

<h2 id="bbre_set_spec_init"><code>bbre_set_spec_init</code></h2>
<p>Initialize a <a href="#bbre_set_spec">bbre_set_spec</a>.</p>

```c
int bbre_set_spec_init(bbre_set_spec **pspec, bbre_alloc_cb alloc);
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

<h2 id="bbre_set_spec_add"><code>bbre_set_spec_add</code>, <code>bbre_set_spec_config</code>, <code>bbre_set</code>, <code>bbre_set_init</code>, <code>bbre_set_init_spec</code>, <code>bbre_set_destroy</code>, <code>bbre_set_match</code></h2>
<p>Add a pattern to a <a href="#bbre_set_spec">bbre_set_spec</a>.</p>

```c
int bbre_set_spec_add(bbre_set_spec *set, const bbre *reg);
int bbre_set_spec_config(bbre_set_spec *b, int option, ...);
typedef struct bbre_set bbre_set;
bbre_set *bbre_set_init(const char *const *regexes_nt, size_t num_regexes);
int bbre_set_init_spec(
    bbre_set **pset, const bbre_set_spec *set_spec, bbre_alloc_cb alloc);
void bbre_set_destroy(bbre_set *set);
int bbre_set_match(
    bbre_set *set, const char *s, size_t n, size_t pos, bbre_u32 idxs_size,
    bbre_u32 *out_idxs, bbre_u32 *out_num_idxs);
```
<ul>
<li><code>set</code> is the set to add the pattern to</li>
<li><code>reg</code> is the pattern to add</li>
</ul>
<p>Returns <a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to add  <code>reg</code> to  <code>set</code>,
0 otherwise.</p>

<h2 id="bbre_fork"><code>bbre_fork</code>, <code>bbre_set_fork</code></h2>
<p>Duplicate a \ref <a href="#bbre">bbre</a> without re-compiling it.</p>

```c
int bbre_fork(bbre *reg, bbre **pout);
int bbre_set_fork(bbre_set *s, bbre_set **out);
```
<p>\param reg The \ref <a href="#bbre">bbre</a> to fork
\param[out] pout A pointer to the output \ref <a href="#bbre">bbre</a> object. *\p pout will be
set to the newly-constructed \ref <a href="#bbre">bbre</a> object.
\return <a href="#BBRE_ERR_MEM">BBRE_ERR_MEM</a> if there was not enough memory to represent the new \ref
<a href="#bbre">bbre</a>, 0 otherwise</p>

