#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define REF_NONE 0

#define AST_REF 0
#define AST_STR 1
#define AST_INT 2

#define ERR_MEM 1
#define ERR_PARSE 2

#define AST_V(v) ((v) >> 2)
#define AST_T(v) ((v) & 3)
#define AST(v, t) ((v) << 2 | (t))

typedef unsigned int u32;
typedef unsigned char u8;

typedef struct ast {
  u32 car, cdr;
} ast;

typedef struct stk {
  u32 *ptr, size, alloc;
} stk;

typedef struct re {
  ast *ast;
  u32 ast_size, ast_alloc;
  stk arg_stk, op_stk;
  stk comp_stk;
  stk prog;
} re;

void *re_alloc(re *re, size_t prev, size_t next, void *ptr) {
  (void)(re);
  if (next) {
    assert(prev || !ptr);
    return realloc(ptr, next);
  } else if (ptr) {
    free(ptr);
  }
  return NULL;
}

void stk_init(re *r, stk *s) {
  (void)(r);
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
  (void)(r);
  assert(s->size);
  return s->ptr[--s->size];
}

u32 stk_peek(re *r, stk *s, u32 idx) {
  (void)(r);
  assert(idx < s->size);
  return s->ptr[s->size - 1 - idx];
}

void re_init(re *re) {
  re->ast = NULL;
  re->ast_size = re->ast_alloc = 0;
  stk_init(re, &re->arg_stk);
  stk_init(re, &re->op_stk);
  stk_init(re, &re->comp_stk);
  stk_init(re, &re->prog);
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
  re->ast[re->ast_size].car = re->ast[re->ast_size].cdr = REF_NONE;
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
      re->ast[prev].cdr = next;
    else
      root = next;
    re->ast[next].car = s[i];
    prev = next;
  }
  return AST(root, AST_STR);
}

void re_ast_dump(re *re, u32 root, u32 ilvl) {
  ast *a = re->ast + root;
  u32 i, first = a->car, rest = a->cdr;
  for (i = 0; i < ilvl; i++)
    printf(" ");
  if (root == REF_NONE) {
    printf("()");
    return;
  }
  printf("(");
  if (AST_T(first) == AST_STR) {
    ast *s = re->ast + first, *c = s;
    for (i = 0; i < s->car; i++) {
      c = re->ast + AST_V(s->cdr);
      printf("%c", c->car);
    }
  } else if (AST_T(first) == AST_INT) {
    printf("%u ", AST_V(first));
  } else {
    printf("\n");
    re_ast_dump(re, AST_V(first), ilvl + 1);
  }
  if (AST_T(rest) == AST_STR) {
    u32 s = AST_V(rest);
    while (s) {
      printf("%c", re->ast[s].car);
      s = re->ast[s].cdr;
    }
  } else if (AST_T(rest) == AST_INT) {
    printf("%u", AST_V(rest));
  } else {
    printf("\n");
    re_ast_dump(re, AST_V(rest), ilvl + 1);
  }
  printf(")%s", ilvl ? "" : "\n");
}

char re_next(const char **s, size_t *sz) {
  assert(*sz);
  (*sz)--;
  return *((*s)++);
}

typedef enum ast_type { CHR, CAT, ALT, QNT, GRP } ast_type;

u32 *re_car(re *re, u32 node) { return &re->ast[node].car; }

u32 *re_cdr(re *re, u32 node) { return &re->ast[node].cdr; }

ast_type re_asttype(re *re, u32 node) { return AST_V(*(re_car(re, node))); }

u32 re_mkast_new(re *re, ast_type type, u32 nargs, u32 *args) {
  u32 i, root = re_ast_new(re), prev = root, next;
  if (!root)
    return root;
  *(re_car(re, root)) = AST(type, AST_INT);
  for (i = 0; i < nargs - 1; i++) {
    if (!(next = re_ast_new(re)))
      return next;
    *(re_cdr(re, prev)) = AST(next, AST_REF);
    *(re_car(re, next)) = args[i];
    prev = next;
  }
  *(re_cdr(re, prev)) = args[i];
  return root;
}

void re_decompast(re *re, u32 root, u32 nargs, u32 *args) {
  u32 i, prev = root, next;
  for (i = 0; i < nargs - 1; i++) {
    next = AST_V(*(re_cdr(re, prev)));
    args[i] = *(re_car(re, next));
    prev = next;
  }
  args[i] = *(re_cdr(re, prev));
}

u32 *re_astarg(re *re, u32 root, u32 n, u32 nargs) {
  if (nargs == 1)
    return re_cdr(re, root);
  else {
    u32 i, next = AST_V(*(re_cdr(re, root)));
    for (i = 0; i < n; i++) {
      next = AST_V(*(re_cdr(re, next)));
    }
    return re_car(re, next);
  }
}

#define MAXREP 100000
#define INFTY (MAXREP + 1)

int re_fold(re *r) {
  while (r->arg_stk.size > 1) {
    u32 args[2], rest;
    args[1] = AST(stk_pop(r, &r->arg_stk), AST_REF);
    args[0] = AST(stk_pop(r, &r->arg_stk), AST_REF);
    rest = re_mkast_new(r, CAT, 2, args);
    if (!rest)
      return ERR_MEM;
    if (stk_push(r, &r->arg_stk, rest))
      return ERR_MEM;
  }
  return 0;
}

int re_fold_alts(re *r) {
  assert(r->arg_stk.size == 1 || r->arg_stk.size == 0);
  if (r->op_stk.size && r->arg_stk.size &&
      AST_V(*re_car(r, stk_peek(r, &r->op_stk, 0))) == ALT)
    /* finish the last alt */
    *re_astarg(r, stk_peek(r, &r->op_stk, 0), 1, 2) =
        AST(stk_pop(r, &r->arg_stk), AST_REF);
  while (r->op_stk.size > 1 &&
         AST_V(*re_car(r, stk_peek(r, &r->op_stk, 0))) == ALT &&
         AST_V(*re_car(r, stk_peek(r, &r->op_stk, 1))) == ALT) {
    u32 right = stk_pop(r, &r->op_stk), left = stk_pop(r, &r->op_stk);
    *re_astarg(r, left, 1, 2) = AST(right, AST_REF);
    if (stk_push(r, &r->op_stk, left))
      return ERR_MEM;
  }
  /* op_stk has either 0 or 1 value above the last group, and it's an alt */
  if (r->op_stk.size &&
      AST_V(*re_car(r, r->op_stk.ptr[r->op_stk.size - 1])) == ALT) {
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
      u32 node, args[3];
      if (!r->arg_stk.size)
        /* not enough values on the stk */
        return ERR_PARSE;
      args[0] = AST(stk_pop(r, &r->arg_stk), AST_REF);
      args[1] = AST(ch == '+', AST_INT);
      args[2] = AST(ch == '?' ? 1 : INFTY, AST_INT);
      if (!(node = re_mkast_new(r, QNT, 3, args)))
        return ERR_MEM;
      if (stk_push(r, &r->arg_stk, node))
        return ERR_MEM;
      break;
    }
    case '|': { /* fold the arg stk into a concat, create alt, push it to the
                   arg stk */
      u32 alt, args[2];
      if (re_fold(r))
        return ERR_MEM;
      args[0] =
          r->arg_stk.size ? AST(stk_pop(r, &r->arg_stk), AST_REF) : REF_NONE;
      args[1] = REF_NONE;
      /* r->arg_stk has either 0 or 1 value */
      if (!(alt = re_mkast_new(r, ALT, 2, args)))
        return ERR_MEM;
      if (stk_push(r, &r->op_stk, alt))
        return ERR_MEM;
      break;
    }
    case '(': { /* push ( to the op stk */
      u32 args[2], grp;
      args[0] = args[1] = REF_NONE;
      grp = re_mkast_new(r, GRP, 2, args);
      if (!grp || stk_push(r, &r->op_stk, grp))
        return ERR_MEM;
      break;
    }
    case ')': { /* fold the arg stk into a concat, fold remaining alts, create
                 group, push it to the arg stk */
      if (re_fold(r) || re_fold_alts(r))
        return ERR_MEM;
      /* arg_stk has either 0 or 1 value */
      if (!r->op_stk.size)
        return ERR_PARSE;
      if (r->arg_stk.size) {
        /* add it to the group */
        *(re_astarg(r, stk_peek(r, &r->op_stk, 0), 0, 2)) =
            AST(stk_pop(r, &r->arg_stk), AST_REF);
      }
      /* pop the group frame into arg_stk */
      if (stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk)))
        return ERR_MEM;
      break;
    }
    default: { /* push to the arg stk */
      u32 args[1], chr;
      args[0] = AST(ch, AST_INT);
      if (!(chr = re_mkast_new(r, CHR, 1, args)) ||
          stk_push(r, &r->arg_stk, chr))
        return ERR_MEM;
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

typedef struct byte_range {
  u8 l, h;
} byte_range;

byte_range mkbr(u8 l, u8 h) {
  byte_range out;
  out.l = l, out.h = h;
  return out;
}

u32 br2u(byte_range br) { return ((u32)br.l) | ((u32)br.h) << 8; }
byte_range u2br(u32 u) { return mkbr(u & 0xFF, u >> 8 & 0xFF); }

#define BYTE_RANGE(l, h) mkbr(l, h)

typedef struct inst {
  u32 l, h;
} inst;

#define INST_OP(i) ((i).l & 3)
#define INST_N(i) ((i).l >> 2)
#define INST_P(i) ((i).h)
#define INST(op, n, p) mkinst((op) | ((n) << 2), (p))

inst mkinst(u32 l, u32 h) {
  inst out;
  out.l = l, out.h = h;
  return out;
}

void re_prog_set(re *r, u32 pc, inst i) {
  r->prog.ptr[pc * 2 + 0] = i.l;
  r->prog.ptr[pc * 2 + 1] = i.h;
}

inst re_prog_get(re *r, u32 pc) {
  inst i;
  i.l = r->prog.ptr[pc * 2 + 0];
  i.h = r->prog.ptr[pc * 2 + 1];
  return i;
}

u32 re_prog_size(re *r) { return r->prog.size >> 1; }

int re_emit(re *r, inst i) {
  if (stk_push(r, &r->prog, 0) || stk_push(r, &r->prog, 0))
    return 1;
  re_prog_set(r, re_prog_size(r) - 1, i);
  return 0;
}

typedef struct compframe {
  u32 root_ref, child_ref, idx, patch_head, patch_tail, pc;
} compframe;

int compframe_push(re *r, compframe c) {
  if (stk_push(r, &r->comp_stk, c.root_ref) ||
      stk_push(r, &r->comp_stk, c.child_ref) ||
      stk_push(r, &r->comp_stk, c.idx) ||
      stk_push(r, &r->comp_stk, c.patch_head) ||
      stk_push(r, &r->comp_stk, c.patch_tail) ||
      stk_push(r, &r->comp_stk, c.pc))
    return ERR_MEM;
  return 0;
}

compframe compframe_pop(re *r) {
  compframe out;
  out.pc = stk_pop(r, &r->comp_stk);
  out.patch_tail = stk_pop(r, &r->comp_stk);
  out.patch_head = stk_pop(r, &r->comp_stk);
  out.idx = stk_pop(r, &r->comp_stk);
  out.child_ref = stk_pop(r, &r->comp_stk);
  out.root_ref = stk_pop(r, &r->comp_stk);
  return out;
}

enum op { RANGE, ASSERT, MATCH, SPLIT };

inst patch_set(re *r, u32 pc, u32 val) {
  inst prev = re_prog_get(r, pc >> 1);
  re_prog_set(r, pc >> 1,
              INST(INST_OP(prev), pc & 1 ? INST_N(prev) : val,
                   pc & 1 ? val : INST_P(prev)));
  return prev;
}

void patch_add(re *r, compframe *f, u32 dest_pc, int p) {
  u32 out_val = dest_pc << 1 | !!p;
  assert(dest_pc);
  printf("patch_add %04X %i\n", dest_pc, p);
  if (!f->patch_head)
    f->patch_head = f->patch_tail = out_val;
  else {
    patch_set(r, f->patch_tail, out_val);
    f->patch_tail = out_val;
  }
}

void patch_merge(re *r, compframe *p, compframe *q) {
  assert(q->patch_head);
  if (!p->patch_head) {
    p->patch_head = q->patch_head;
    p->patch_tail = q->patch_tail;
    return;
  }
  patch_set(r, p->patch_tail, q->patch_head);
  p->patch_tail = q->patch_tail;
}

void patch(re *r, compframe *p, u32 dest_pc) {
  u32 i = p->patch_head;
  while (i != p->patch_tail) {
    inst prev = patch_set(r, i, dest_pc);
    i = i & 1 ? INST_P(prev) : INST_N(prev);
  }
  patch_set(r, i, dest_pc);
  p->patch_head = p->patch_tail = REF_NONE;
}

int re_compile(re *r, u32 root) {
  compframe initial_frame, returned_frame;
  initial_frame.root_ref = root;
  initial_frame.child_ref = REF_NONE;
  initial_frame.patch_head = REF_NONE;
  initial_frame.patch_tail = REF_NONE;
  initial_frame.idx = 0;
  initial_frame.pc = 1;
  if (compframe_push(r, initial_frame))
    return ERR_MEM;
  if (stk_push(r, &r->prog, 0) || stk_push(r, &r->prog, 0))
    return ERR_MEM;
  while (r->comp_stk.size) {
    compframe frame = compframe_pop(r);
    ast_type type;
    u32 args[4], child_ref = REF_NONE;
    assert(frame.root_ref);
    type = AST_V(*re_car(r, frame.root_ref));
    if (type == CHR) {
      re_decompast(r, frame.root_ref, 1, args);
      args[0] = AST_V(args[0]);
      if (re_emit(r, INST(RANGE, 0, br2u(BYTE_RANGE(args[0], args[0])))))
        return ERR_MEM;
      patch_add(r, &frame, re_prog_size(r) - 1, 0);
    } else if (type == CAT) {
      re_decompast(r, frame.root_ref, 2, args);
      args[0] = AST_V(args[0]);
      args[1] = AST_V(args[1]);
      if (!frame.child_ref) {
        /* before left child */
        frame.child_ref = child_ref = args[0]; /* push left child */
      } else if (frame.child_ref == args[0]) {
        /* after left child */
        patch(r, &returned_frame, re_prog_size(r));
        frame.child_ref = child_ref = args[1]; /* push right child */
      } else if (frame.child_ref == args[1]) {
        /* after right child */
        patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == ALT) {
      re_decompast(r, frame.root_ref, 2, args);
      args[0] = AST_V(args[0]);
      args[1] = AST_V(args[1]);
      if (!frame.child_ref) {
        /* before left child */
        if (re_emit(r, INST(SPLIT, 0, 0)))
          return ERR_MEM;
        if (args[0])
          frame.child_ref = child_ref = args[0];
        else {
          patch_add(r, &frame, frame.pc, 0);
          if (args[1])
            frame.child_ref = child_ref = args[1];
        }
      } else if (args[0] && frame.child_ref == args[0]) {
        /* after left child */
        patch_set(r, frame.pc << 1, returned_frame.pc);
        patch_merge(r, &frame, &returned_frame);
        if (args[1])
          frame.child_ref = child_ref = args[1];
        else
          patch_add(r, &frame, frame.pc, 1);
      } else if (args[1] && frame.child_ref == args[1]) {
        /* after right child */
        patch_set(r, frame.pc << 1 | 1, returned_frame.pc);
        patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == QNT) {
      u32 child, min, max;
      re_decompast(r, frame.root_ref, 3, args);
      printf("%i %i %i\n", type, frame.root_ref, frame.child_ref);
      child = args[0] = AST_V(args[0]);
      min = args[1] = AST_V(args[1]);
      max = args[2] = AST_V(args[2]);
      if (frame.idx < min) {
        /* generate child min times */
        if (frame.idx)
          patch(r, &returned_frame, re_prog_size(r));
        frame.child_ref = child_ref = child;
      } else if (max == INFTY && frame.idx == min) {
        /* before infinite bound */
        if (frame.idx)
          patch(r, &returned_frame, re_prog_size(r));
        if (re_emit(r, INST(SPLIT, re_prog_size(r) + 1, 0)))
          return ERR_MEM;
        patch_add(r, &frame, re_prog_size(r) - 1, 1);
        frame.child_ref = child_ref = child;
      } else if (max == INFTY && frame.idx == min + 1) {
        /* after infinite bound */
        patch(r, &returned_frame, frame.pc);
      } else if (frame.idx < max) {
        /* before maximum bound */
        if (frame.idx == min)
          patch(r, &returned_frame, re_prog_size(r));
        if (re_emit(r, INST(SPLIT, re_prog_size(r) + 1, 0)))
          return ERR_MEM;
        patch_add(r, &frame, re_prog_size(r) - 1, 1);
        frame.child_ref = child_ref = child;
      } else if (frame.idx == max) {
        /* after maximum bound */
        patch_merge(r, &frame, &returned_frame);
      }
      frame.idx++;
    } else if (type == GRP) {
      u32 child;
      re_decompast(r, frame.root_ref, 2, args);
      child = args[0] = AST_V(args[0]);
      if (child && !frame.child_ref) {
        /* before child */
        if (re_emit(r, INST(MATCH, re_prog_size(r) + 1, 1)))
          return ERR_MEM;
        frame.child_ref = child_ref = child;
      } else if (child && frame.child_ref) {
        /* after child */
        patch(r, &returned_frame, re_prog_size(r));
        if (re_emit(r, INST(MATCH, 0, 2)))
          return ERR_MEM;
        patch_add(r, &frame, re_prog_size(r) - 1, 0);
      } else {
        /* no child */
        if (re_emit(r, INST(MATCH, re_prog_size(r) + 1, 1)))
          return ERR_MEM;
        if (re_emit(r, INST(MATCH, 0, 2)))
          return ERR_MEM;
        patch_add(r, &frame, re_prog_size(r) - 1, 0);
      }
    }
    if (child_ref) {
      compframe up_frame;
      /* should we push a child? */
      if (compframe_push(r, frame))
        return ERR_MEM;
      up_frame.root_ref = child_ref;
      up_frame.child_ref = REF_NONE;
      up_frame.patch_head = up_frame.patch_tail = REF_NONE;
      up_frame.idx = 0;
      up_frame.pc = re_prog_size(r);
      if (compframe_push(r, up_frame))
        return ERR_MEM;
    }
    returned_frame = frame;
  }
  assert(!r->comp_stk.size);
  patch(r, &returned_frame, re_prog_size(r));
  if (re_emit(r, INST(MATCH, 0, 0)))
    return ERR_MEM;
  return 0;
}

void re_prog_dump(re *r) {
  u32 i;
  for (i = 0; i < re_prog_size(r); i++) {
    inst ins = re_prog_get(r, i);
    const char *ops[] = {"RANGE", "ASSRT", "MATCH", "SPLIT"};
    printf("%04X %s %04X %04X\n", i, ops[INST_OP(ins)], INST_N(ins),
           INST_P(ins));
  }
}

typedef struct thrdspec {
  u32 pc, slot;
} thrdspec;

typedef struct sset {
  u32 *sparse, sparse_alloc;
  thrdspec *dense;
  u32 dense_size, dense_alloc;
} sset;

int sset_alloc(re *r, sset *s) {
  size_t next_alloc = r->prog.size;
  u32 *next_sparse;
  thrdspec *next_dense;
  if (!next_alloc)
    return 0;
  if (!(next_sparse = re_alloc(r, sizeof(u32) * s->sparse_alloc,
                               sizeof(u32) * next_alloc, s->sparse)))
    return 1;
  s->sparse = next_sparse;
  if (!(next_dense = re_alloc(r, sizeof(thrdspec) * s->dense_alloc,
                              sizeof(thrdspec) * next_alloc, s->dense)))
    return 1;
  s->dense = next_dense;
  return 0;
}

void sset_init(re *r, sset *s) {
  (void)(r);
  s->sparse = NULL;
  s->sparse_alloc = 0;
  s->dense = NULL;
  s->dense_alloc = s->dense_size = 0;
}

void sset_clear(sset *s) { s->dense_size = 0; }

void sset_destroy(re *r, sset *s) {
  re_alloc(r, sizeof(u32) * s->sparse_alloc, 0, s->sparse);
  re_alloc(r, sizeof(thrdspec) * s->dense_alloc, 0, s->dense);
}

void sset_add(sset *s, thrdspec spec) {
  assert(spec.pc < s->dense_alloc);
  assert(s->dense_size < s->dense_alloc);
  s->dense[s->dense_size] = spec;
  s->sparse[spec.pc] = s->dense_size++;
}

int sset_memb(sset *s, u32 pc) {
  assert(pc < s->dense_alloc);
  return s->sparse[pc] < s->dense_size && s->dense[s->sparse[pc]].pc == pc;
}

typedef struct save_slots {
  size_t *slots, slots_size, slots_alloc, last_empty, per_thrd;
} save_slots;

void save_slots_init(re *r, save_slots *s) {
  (void)r;
  s->slots = NULL;
  s->slots_size = s->slots_alloc = s->last_empty = s->per_thrd = 0;
}

void save_slots_destroy(re *r, save_slots *s) {
  re_alloc(r, sizeof(size_t) * s->slots_alloc, 0, s->slots);
}

void save_slots_clear(save_slots *s, size_t per_thrd) {
  s->slots_size = 0, s->last_empty = 0, s->per_thrd = per_thrd;
}

u32 save_slots_new(re *r, save_slots *s);
u32 save_slots_incref(save_slots *s, u32 ref);
u32 save_slots_decref(save_slots *s, u32 ref);

typedef struct exec_nfa {
  sset a, b, c;
  save_slots slots;
} exec_nfa;

void exec_nfa_init(re *r, exec_nfa *n) {
  sset_init(r, &n->a);
  sset_init(r, &n->b);
  sset_init(r, &n->c);
}

#include <string.h>

int main(void) {
  re r;
  u32 root;
  const char *g = "(a*b)*";
  re_init(&r);
  printf("parse: %u\n", re_parse(&r, g, strlen(g), &root));
  re_ast_dump(&r, root, 0);
  printf("%u\n", re_compile(&r, root));
  re_prog_dump(&r);
}
