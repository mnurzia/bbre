# Syntax

`bbre` supports syntax that is similar to many other regex engines, notably [re2](https://github.com/google/re2/wiki/Syntax). 

## Single-Character Expressions 

```
.           any character except newline (includes newline if 's' flag is set)
\123        octal character (up to three octal digits)
\xAB        hex character (two hex digits)
\x{ABCDEF}  hex character (up to six digits)
\a          bell            (\x07)
\f          form feed       (\x0C)
\t          horizontal tab  (\x09)
\n          newline         (\x0A)
\r          carriage return (\x0D)
\v          vertical tab    (\x0B)
\?          question mark   ('?')
\*          asterisk        ('*')
\+          plus            ('+')
\(          open paren      ('(')
\)          close paren     (')')
\[          open square     ('[')
\]          close square    (']')
\{          open curly      ('{')
\}          close curly     ('}')
\|          vertical bar    ('|')
\^          caret           ('^')
\$          dollar sign     ('$')
\-          dash            ('-')
\.          dot             ('.')
\\          slash           ('\')
```

## Character Classes

```
[a]         match a only
[a-z]       match anything in the range a-z
[xa-z]      match x or anything in the range a-z
[^a]        match everything except a
[^a-z]      match everything except anything in the range a-z
[]]         match close square bracket only
```

In addition to every single-character expression except `.`, the following escapes can be used both within and outside of character classes:
```
\d          (perl) digits               [0-9]
\D          (perl) non-digits           [^0-9]
\s          (perl) whitespace           [\t\n\f\r ]
\S          (perl) non-whitespace       [^\t\n\f\r ]
\w          (perl) word characters      [0-9A-Za-z_]
\W          (perl) non-word characters  [^0-9A-Za-z_]
\px         named unicode property (1 character)
\p{xyz}     named unicode property
\Px         inverted named unicode property (1 character)
\P{xyz}     inverted named unicode property
```

## Builtin Character Classes
```
[:alnum:]      [0-9A-Za-z]
[:alpha:]      [A-Za-z]
[:ascii:]      [\x00-\x7F]
[:blank:]      [\t\ ]
[:cntrl:]      [\x00-\x1F\x7F]
[:digit:]      [0-9]
[:graph:]      [!-\~]
[:lower:]      [a-z]
[:print:]      [\ -\~]
[:punct:]      [!-/:-@\[-`\{-\~]
[:space:]      [\t-\r\ ]
[:perl_space:] [\t-\n\x0C-\r\ ]
[:upper:]      [A-Z]
[:word:]       [0-9A-Z_a-z]
[:xdigit:]     [0-9A-Fa-f]
```

## Quantifiers
```
x*          zero or more of x, prefer more
x+          one or more of x, prefer more
x?          zero or one of x, prefer one
x*?         zero or more of x, prefer fewer
x+?         one or more of x, prefer fewer
x??         zero or one of x, prefer zero
x{n}        x repeated n times
x{n,}       x repeated n or more times, prefer more
x{m,n}      x repeated m or m+1 or m+2 ... or n times, prefer more
x{n,}?      x repeated n or more times, prefer fewer
x{m,n}?     x repeated m or m+1 or m+2 ... or n times, prefer fewer
```

## Composite Operators
```
x|y         alternation: match either x or y (prefer x)
xy          concatenation: match x then y
```

## Groups
```
(xyz)           numbered capturing group matching xyz
(?<name>xyz)    named and numbered capturing group matching xyz
(?P<name>xyz)   named and numbered capturing group matching xyz
(?:xyz)         noncapturing group matching xyz
(?flags:xyz)    noncapturing group matching xyz with flags enabled
(?-flags:xyz)   noncapturing group matching xyz with flags disabled
(?flags)        enable flags for the remainder of the current group
(?-flags)       disable flags for the remainder of the current group
```

### Group Flags
```
i           insensitive matching (Unicode-aware)
m           multiline matching (^$ match the beginning and end of lines)
s           stream mode (. matches \n)
U           swap quantifier greediness (x* becomes x*?, x+? becomes x+, etc.)
```

## Empty Assertions
```
\A          beginning of text
\z          end of text
\B          not a word boundary
\b          word boundary
^           beginning of text (also beginning if line of `m` flag is active)
$           end of text (also end of line if `m` flag is active)
```

## Miscellaneous
```
\C          matches any *byte* (warning -- may break UTF-8 encodings!)
\Q...\E     quoted text: everything between \Q / \E is matched verbatim
```
