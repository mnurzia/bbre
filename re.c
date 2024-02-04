#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define REF_NONE 0

#define AST_REF 0
#define AST_STR 1
#define AST_INT 2

#define AST_V(v) ((v) >> 2)
#define AST_T(v) ((v) & 3)
#define AST(v, t) ((v) << 2 | (t))

typedef unsigned int u32;

typedef struct ast {
  u32 first, rest;
} ast;

typedef struct stk {
  u32 *ptr, size, alloc;
} stk;

typedef struct re {
  ast *ast;
  u32 ast_size, ast_alloc;
  stk arg_stk, op_stk;
} re;

void *re_alloc(re *re, size_t prev, size_t next, void *ptr) {
  if (next) {
    assert(prev || !ptr);
    return realloc(ptr, next);
  } else if (ptr) {
    free(ptr);
  }
  return NULL;
}

void stk_init(re *r, stk *s) {
  s->ptr = NULL;
  s->size = s->alloc = 0;
}

void stk_destroy(re *r, stk *s) {
  re_alloc(r, sizeof(*s->ptr) * s->alloc, 0, s->ptr);
}

int stk_push(re *r, stk *s, u32 v) {
  if (s->size == s->alloc) {
    size_t next_alloc = (s->alloc ? (s->alloc * 2) : 16);
    u32 *out = re_alloc(r, sizeof(*s->ptr) * s->alloc,
                        sizeof(*s->ptr) * next_alloc, s->ptr);
    if (!out)
      return 1;
    s->alloc = next_alloc;
    s->ptr = out;
  }
  s->ptr[s->size++] = v;
  return 0;
}

u32 stk_pop(re *r, stk *s) {
  assert(s->size);
  return s->ptr[--s->size];
}

u32 stk_peek(re *r, stk *s, u32 idx) {
  assert(idx < s->size);
  return s->ptr[s->size - 1 - idx];
}

void re_init(re *re) {
  re->ast = NULL;
  re->ast_size = re->ast_alloc = 0;
  stk_init(re, &re->arg_stk);
  stk_init(re, &re->op_stk);
}

void re_destroy(re *re) {
  re_alloc(re, re->ast_alloc * sizeof(*re->ast), 0, re->ast);
  stk_destroy(re, &re->op_stk);
  stk_destroy(re, &re->arg_stk);
}

u32 re_ast_new(re *re) {
  if (re->ast_size == re->ast_alloc)
    re->ast = re_alloc(re, re->ast_alloc * sizeof(ast),
                       (re->ast_alloc ? re->ast_alloc * 2 : 16) * sizeof(ast),
                       re->ast);
  if (!re->ast)
    return REF_NONE;
  re->ast[re->ast_size].first = re->ast[REF_NONE].rest = REF_NONE;
  if (re->ast_size == REF_NONE) {
    re->ast_size++;
    return re_ast_new(re);
  }
  return re->ast_size++;
}

u32 re_ast_str(re *re, const char *s, size_t sz) {
  u32 root = REF_NONE, i, next = root, prev = root;
  for (i = 0; i < sz; i++) {
    next = re_ast_new(re);
    if (next == REF_NONE)
      return next;
    if (prev != REF_NONE)
      re->ast[prev].rest = next;
    else
      root = next;
    re->ast[next].first = s[i];
    prev = next;
  }
  return AST(root, AST_STR);
}

void re_ast_dump(re *re, u32 root, u32 ilvl) {
  ast *a = re->ast + root;
  u32 i, first = a->first, rest = a->rest;
  for (i = 0; i < ilvl; i++)
    printf(" ");
  if (root == REF_NONE) {
    printf("()");
    return;
  }
  printf("(");
  if (AST_T(first) == AST_STR) {
    ast *s = re->ast + first, *c = s;
    for (i = 0; i < s->first; i++) {
      c = re->ast + AST_V(s->rest);
      printf("%c", c->first);
    }
  } else if (AST_T(first) == AST_INT) {
    printf("%u", AST_V(first));
  } else {
    printf("\n");
    re_ast_dump(re, AST_V(first), ilvl + 1);
  }
  if (AST_T(rest) == AST_STR) {
    u32 s = AST_V(rest);
    while (s) {
      printf("%c", re->ast[s].first);
      s = re->ast[s].rest;
    }
  } else if (AST_T(rest) == AST_INT) {
    printf("%u", AST_V(rest));
  } else {
    printf("\n");
    re_ast_dump(re, AST_V(rest), ilvl + 1);
  }
  printf(")");
}

char re_next(const char **s, size_t *sz) {
  assert(*sz);
  (*sz)--;
  return *((*s)++);
}

typedef enum ast_type { CHR, CAT, ALT, QNT, GRP } ast_type;

u32 *re_first(re *re, u32 node) { return &re->ast[node].first; }

u32 *re_rest(re *re, u32 node) { return &re->ast[node].rest; }

u32 re_mkast(re *re, ast_type type) {
  u32 out = re_ast_new(re), data = re_ast_new(re);
  if (!out || !data)
    return out;
  *(re_first(re, out)) = AST(type, AST_INT);
  *(re_rest(re, out)) = AST(data, AST_REF);
  return out;
}

u32 re_astchild(re *re, u32 node, u32 child) {
  u32 next = re_ast_new(re);
  if (!next)
    return next;
  *(re_first(re, next)) = AST(child, AST_REF);
  *(re_rest(re, next)) = *(re_first(re, AST_V(*(re_rest(re, node)))));
  *(re_first(re, AST_V(*(re_rest(re, node))))) = AST(next, AST_REF);
  return next;
}

u32 re_astdata(re *re, u32 node, u32 data) {
  u32 out = *(re_rest(re, AST_V(*(re_rest(re, node)))));
  *(re_rest(re, AST_V(*(re_rest(re, node))))) = data;
  return out;
}

#define ERR_MEM 1
#define ERR_PARSE 2

#define MAXREP 100000
#define INFTY (MAXREP + 1)

int re_fold(re *r) {
  while (r->arg_stk.size > 1) {
    u32 rest = re_mkast(r, CAT);
    u32 right = stk_pop(r, &r->arg_stk), left = stk_pop(r, &r->arg_stk);
    re_ast_dump(r, left, 0);
    re_ast_dump(r, right, 0);
    if (!rest)
      return ERR_MEM;
    if (!re_astchild(r, rest, right) || !re_astchild(r, rest, left))
      return ERR_MEM;
    if (stk_push(r, &r->arg_stk, rest))
      return ERR_MEM;
  }
  return 0;
}

int re_fold_alts(re *r) {
  assert(r->arg_stk.size == 1 || r->arg_stk.size == 0);
  if (r->op_stk.size && r->arg_stk.size &&
      AST_V(*re_first(r, r->op_stk.ptr[r->op_stk.size - 1])) == ALT)
    /* finish the last alt */
    if (!re_astchild(r, r->op_stk.ptr[r->op_stk.size - 1],
                     stk_pop(r, &r->arg_stk)))
      return ERR_MEM;
  while (r->op_stk.size > 1 &&
         AST_V(*re_first(r, r->op_stk.ptr[r->op_stk.size - 1])) == ALT &&
         AST_V(*re_first(r, r->op_stk.ptr[r->op_stk.size - 2])) == ALT) {
    u32 right = stk_pop(r, &r->op_stk), left = stk_pop(r, &r->op_stk);
    if (!re_astchild(r, left, right))
      return ERR_MEM;
    if (stk_push(r, &r->op_stk, left))
      return ERR_MEM;
  }
  /* op_stk has either 0 or 1 value above the last group, and it's an alt */
  if (r->op_stk.size &&
      AST_V(*re_first(r, r->op_stk.ptr[r->op_stk.size - 1])) == ALT) {
    /* push it to arg_stk */
    if (stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk)))
      return ERR_MEM;
  }
  return 0;
}

int re_parse(re *r, const char *s, size_t sz, u32 *root) {
  char ch;
  while (sz) {
    switch (ch = re_next(&s, &sz)) {
    case '*':
    case '+':
    case '?': { /* pop one from arg stk, create quant, push to arg stk */
      u32 node, data, child;
      if (!r->arg_stk.size)
        /* not enough values on the stk */
        return ERR_PARSE;
      child = stk_pop(r, &r->arg_stk);
      if (!(node = re_mkast(r, QNT)) || !(data = re_ast_new(r)))
        return ERR_MEM;
      if (!re_astchild(r, node, child))
        return ERR_MEM;
      r->ast[data].first = AST(ch == '+', AST_INT);
      r->ast[data].rest = AST(ch == '?' ? 1 : INFTY, AST_INT);
      re_astdata(r, node, AST(data, AST_REF));
      if (stk_push(r, &r->arg_stk, node))
        return ERR_MEM;
      break;
    }
    case '|': { /* fold the arg stk into a concat, create alt, push it to the
                   arg stk */
      u32 alt;
      if (re_fold(r))
        return ERR_MEM;
      /* r->arg_stk has either 0 or 1 value */
      if (!(alt = re_mkast(r, ALT)))
        return ERR_MEM;
      if (!re_astchild(r, alt,
                       r->arg_stk.size ? stk_pop(r, &r->arg_stk) : REF_NONE))
        return ERR_MEM;
      if (stk_push(r, &r->op_stk, alt))
        return ERR_MEM;
      break;
    }
    case '(': { /* push ( to the op stk */
      u32 item = re_mkast(r, GRP);
      if (item == REF_NONE || !stk_push(r, &r->op_stk, item))
        return ERR_MEM;
      break;
    }
    case ')': { /* fold the arg stk into a concat, fold remaining alts, create
                 group, push it to the arg stk */
      if (re_fold(r) || re_fold_alts(r))
        return ERR_MEM;
      /* arg_stk has either 0 or 1 value */
      if (r->arg_stk.size) {
        /* add it to the group */
        if (!re_astchild(r, r->op_stk.ptr[r->op_stk.size - 1],
                         stk_pop(r, &r->arg_stk)))
          return ERR_MEM;
      }
      /* pop the group frame into arg_stk */
      if (stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk)))
        return ERR_MEM;
      break;
    }
    default: { /* push to the arg stk */
      u32 item = re_mkast(r, CHR);
      if (item == REF_NONE || stk_push(r, &r->arg_stk, item))
        return ERR_MEM;
      re_astdata(r, item, AST(ch, AST_INT));
      break;
    }
    }
  }
  if (re_fold(r) || re_fold_alts(r))
    return ERR_MEM;
  if (r->op_stk.size)
    return ERR_PARSE;
  *root = r->arg_stk.size ? stk_pop(r, &r->arg_stk) : REF_NONE;
  return 0;
}

int main(void) {
  re r;
  u32 root;
  re_init(&r);
  printf("%u\n", re_parse(&r, "a|b", 3, &root));
  re_ast_dump(&r, root, 0);
}
