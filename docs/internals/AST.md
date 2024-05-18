# AST

This page describes the implementation of the AST.

The engine builds an AST from the input regexp. The AST is analyzed and then compiled into the NFA program.

Each node in the AST has a type. Nodes have children and associated data depending on their type.

## AST Reference
### CHR
A single character.

#### Example: `a`
![CHR AST example](generated/ast/chr_ast.svg)

![CHR program example](generated/ast/chr_prog.svg)

### CAT
The concatenation of two regular expressions.
#### Arguments:
  -   Argument 0: left child tree (AST)
  -   Argument 1: right child tree (AST)

#### Example: `lr`
![CAT AST example](generated/ast/cat_ast.svg)

![CAT program example](generated/ast/cat_prog.svg)

### ALT
The alternation of two regular expressions.
#### Arguments:
  -   Argument 0: primary alternation tree (AST)
  -   Argument 1: secondary alternation tree (AST)

#### Example: `l|r`
![ALT AST example](generated/ast/alt_ast.svg)

![ALT program example](generated/ast/alt_prog.svg)

### QUANT
A repeated regular expression.
#### Arguments:
  -   Argument 0: child tree (AST)
  -   Argument 1: lower bound, always <= upper bound (number)
  -   Argument 2: upper bound, might be the constant `INFTY` (number)

#### Example: `a+`
![QUANT AST example](generated/ast/quant_ast.svg)

![QUANT program example](generated/ast/quant_prog.svg)

### UQUANT
Like `QUANT`, but not greedy.
#### Arguments:
  -   Argument 0: child tree (AST)
  -   Argument 1: lower bound, always <= upper bound (number)
  -   Argument 2: upper bound, might be the constant `INFTY` (number)

#### Example: `(a*?)`
![UQUANT AST example](generated/ast/uquant_ast.svg)

![UQUANT program example](generated/ast/uquant_prog.svg)

### GROUP
A matching group.
#### Arguments:
  -   Argument 0: child tree (AST)
  -   Argument 1: group flags, bitset of `enum group_flag` (number)
  -   Argument 2: scratch used by the parser to store old flags (number)

#### Example: `(a)`
![GROUP AST example](generated/ast/group_ast.svg)

![GROUP program example](generated/ast/group_prog.svg)

### IGROUP
An inline group.
#### Arguments:
  -   Argument 0: child tree (AST)
  -   Argument 1: group flags, bitset of `enum group_flag` (number)
  -   Argument 2: scratch used by the parser to store old flags (number)

#### Example: `(?i)a`
![IGROUP AST example](generated/ast/igroup_ast.svg)

![IGROUP program example](generated/ast/igroup_prog.svg)

### CLS
A character class.
#### Arguments:
  -   Argument 0: REF_NONE or another CLS node in the charclass (AST)
  -   Argument 1: character range begin (number)
  -   Argument 2: character range end (number)

#### Example: `[a-zA-Z]`
![CLS AST example](generated/ast/cls_ast.svg)

![CLS program example](generated/ast/cls_prog.svg)

### ICLS
An inverted character class.
#### Arguments:
  -   Argument 0: REF_NONE or another CLS node in the charclass (AST)
  -   Argument 1: character range begin (number)
  -   Argument 2: character range end (number)

#### Example: `[^a-zA-Z]`
![ICLS AST example](generated/ast/icls_ast.svg)

![ICLS program example](generated/ast/icls_prog.svg)

### ANYBYTE
Matches any byte.

#### Example: `\C`
![ANYBYTE AST example](generated/ast/anybyte_ast.svg)

![ANYBYTE program example](generated/ast/anybyte_prog.svg)

### AASSERT
Empty assertion.
#### Arguments:
  -   Argument 0: assertion flags, bitset of `enum assert_flag` (number)

#### Example: `\b`
![AASSERT AST example](generated/ast/aassert_ast.svg)

![AASSERT program example](generated/ast/aassert_prog.svg)

