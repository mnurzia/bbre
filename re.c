#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "re.h"

#define REF_NONE 0

#define ERR_MEM 1
#define ERR_PARSE 2

typedef struct ast {
  u32 car, cdr;
} ast;

typedef struct stk {
  u32 *ptr, size, alloc;
} stk;

struct re {
  ast *ast;
  u32 ast_size, ast_alloc, ast_root, ast_sets;
  stk arg_stk, op_stk, comp_stk, prog;
};

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

int re_parse(re *r, const char *s, size_t sz, u32 *root);

re *re_init(const char *regex) {
  re *r = (re *)malloc(sizeof(re));
  if (!r)
    return r;
  r->ast = NULL;
  r->ast_size = r->ast_alloc = r->ast_root = r->ast_sets = 0;
  stk_init(r, &r->arg_stk), stk_init(r, &r->op_stk), stk_init(r, &r->comp_stk);
  stk_init(r, &r->prog);
  if (regex) {
    if (re_parse(r, regex, strlen(regex), &r->ast_root)) {
      re_destroy(r);
      return NULL;
    } else {
      r->ast_sets = 1;
    }
  }
  return r;
}

void re_destroy(re *re) {
  re_alloc(re, re->ast_alloc * sizeof(*re->ast), 0, re->ast);
  stk_destroy(re, &re->op_stk), stk_destroy(re, &re->arg_stk),
      stk_destroy(re, &re->comp_stk);
  stk_destroy(re, &re->prog);
  re_alloc(re, sizeof(*re), 0, re);
}

u32 re_ast_new(re *re) {
  if (re->ast_size == re->ast_alloc) {
    u32 next_alloc = (re->ast_alloc ? re->ast_alloc * 2 : 16);
    re->ast = re_alloc(re, re->ast_alloc * sizeof(ast),
                       next_alloc * sizeof(ast), re->ast);
    if (!re->ast)
      return REF_NONE;
    re->ast_alloc = next_alloc;
  }
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
  return root;
}

typedef enum ast_type { CHR, CAT, ALT, QUANT, GROUP, FORK } ast_type;

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

u32 *re_car(re *re, u32 node) { return &re->ast[node].car; }

u32 *re_cdr(re *re, u32 node) { return &re->ast[node].cdr; }

ast_type re_asttype(re *re, u32 node) { return *(re_car(re, node)); }

u32 re_mkast_new(re *re, ast_type type, u32 nargs, u32 *args) {
  u32 i, root = re_ast_new(re), prev = root, next;
  if (!root)
    return root;
  *(re_car(re, root)) = type;
  for (i = 0; i < nargs - 1; i++) {
    if (!(next = re_ast_new(re)))
      return next;
    *(re_cdr(re, prev)) = next;
    *(re_car(re, next)) = args[i];
    prev = next;
  }
  *(re_cdr(re, prev)) = args[i];
  return root;
}

void re_decompast(re *re, u32 root, u32 nargs, u32 *args) {
  u32 i, prev = root, next;
  for (i = 0; i < nargs - 1; i++) {
    next = *(re_cdr(re, prev));
    args[i] = *(re_car(re, next));
    prev = next;
  }
  args[i] = *(re_cdr(re, prev));
}

u32 *re_astarg(re *re, u32 root, u32 n, u32 nargs) {
  u32 i, prev = root, next;
  for (i = 0; i < nargs - 1; i++) {
    next = *(re_cdr(re, prev));
    if (i == n)
      return re_car(re, next);
    prev = next;
  }
  return re_cdr(re, prev);
}

void re_ast_dump(re *r, u32 root, u32 ilvl) {
  ast *a = r->ast + root;
  u32 i, first = a->car, rest = a->cdr;
  printf("%04u ", root);
  for (i = 0; i < ilvl; i++)
    printf(" ");
  if (root == REF_NONE) {
    printf("<eps>\n");
  } else if (first == CHR) {
    printf("CHR %04X\n", rest);
  } else if (first == CAT) {
    printf("CAT\n");
    re_ast_dump(r, *re_astarg(r, root, 0, 2), ilvl + 1);
    re_ast_dump(r, *re_astarg(r, root, 1, 2), ilvl + 1);
  } else if (first == ALT) {
    printf("ALT\n");
    re_ast_dump(r, *re_astarg(r, root, 0, 2), ilvl + 1);
    re_ast_dump(r, *re_astarg(r, root, 1, 2), ilvl + 1);
  } else if (first == GROUP) {
    printf("GRP flag=%u\n", *re_astarg(r, root, 1, 2));
    re_ast_dump(r, *re_astarg(r, root, 0, 2), ilvl + 1);
  } else if (first == QUANT) {
    printf("QNT min=%u max=%u\n", *re_astarg(r, root, 1, 3),
           *re_astarg(r, root, 2, 3));
    re_ast_dump(r, *re_astarg(r, root, 0, 3), ilvl + 1);
  } else if (first == FORK) {
    printf("FORK\n");
    re_ast_dump(r, *re_astarg(r, root, 0, 2), ilvl + 1);
    re_ast_dump(r, *re_astarg(r, root, 1, 2), ilvl + 1);
  }
}

int re_union(re *r, const char *regex) { /* add a FORK here */
  int err = 0;
  if (!r->ast_sets && (err = re_parse(r, regex, strlen(regex), &r->ast_root))) {
    return err;
  } else {
    u32 fork_args[2] = {0}, next_root;
    if ((err = re_parse(r, regex, strlen(regex), fork_args + 1)))
      return ERR_MEM;
    fork_args[0] = r->ast_root;
    if (!(next_root = re_mkast_new(r, FORK, 2, fork_args)))
      return ERR_MEM;
    r->ast_root = next_root;
  }
  return err;
}

char re_next(const char **s, size_t *sz) {
  assert(*sz);
  (*sz)--;
  return *((*s)++);
}

#define MAXREP 100000
#define INFTY (MAXREP + 1)

int re_fold(re *r) {
  while (r->arg_stk.size > 1) {
    u32 args[2], rest;
    args[1] = stk_pop(r, &r->arg_stk);
    args[0] = stk_pop(r, &r->arg_stk);
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
      *re_car(r, stk_peek(r, &r->op_stk, 0)) == ALT)
    /* finish the last alt */
    *re_astarg(r, stk_peek(r, &r->op_stk, 0), 1, 2) = stk_pop(r, &r->arg_stk);
  while (r->op_stk.size > 1 && *re_car(r, stk_peek(r, &r->op_stk, 0)) == ALT &&
         *re_car(r, stk_peek(r, &r->op_stk, 1)) == ALT) {
    u32 right = stk_pop(r, &r->op_stk), left = stk_pop(r, &r->op_stk);
    *re_astarg(r, left, 1, 2) = right;
    if (stk_push(r, &r->op_stk, left))
      return ERR_MEM;
  }
  /* op_stk has either 0 or 1 value above the last group, and it's an alt */
  if (r->op_stk.size && *re_car(r, r->op_stk.ptr[r->op_stk.size - 1]) == ALT) {
    /* push it to arg_stk */
    if (stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk)))
      return ERR_MEM;
  }
  return 0;
}

int re_parse(re *r, const char *s, size_t sz, u32 *root) {
  while (sz) {
    char ch = re_next(&s, &sz);
    u32 args[3] = {REF_NONE}, res = REF_NONE;
    if (ch == '*' || ch == '+' || ch == '?') {
      /* pop one from arg stk, create quant, push to arg stk */
      if (!r->arg_stk.size)
        return ERR_PARSE; /* not enough values on the stk */
      args[0] = stk_pop(r, &r->arg_stk);
      args[1] = ch == '+', args[2] = ch == '?' ? 1 : INFTY;
      if (!(res = re_mkast_new(r, QUANT, 3, args)))
        return ERR_MEM;
      if (stk_push(r, &r->arg_stk, res))
        return ERR_MEM;
    } else if (ch == '|') {
      /* fold the arg stk into a concat, create alt, push it to the arg stk */
      if (re_fold(r))
        return ERR_MEM;
      args[0] = r->arg_stk.size ? stk_pop(r, &r->arg_stk) : REF_NONE;
      args[1] = REF_NONE; /* r->arg_stk has either 0 or 1 value */
      if (!(res = re_mkast_new(r, ALT, 2, args)))
        return ERR_MEM;
      if (stk_push(r, &r->op_stk, res))
        return ERR_MEM;
    } else if (ch == '(') {
      if (!(res = re_mkast_new(r, GROUP, 2, args)) ||
          stk_push(r, &r->op_stk, res))
        return ERR_MEM;
    } else if (ch == ')') {
      /* fold the arg stk into a concat, fold remaining alts, create group,
       * push it to the arg stk */
      if (re_fold(r) || re_fold_alts(r))
        return ERR_MEM;
      /* arg_stk has either 0 or 1 value */
      if (!r->op_stk.size)
        return ERR_PARSE;
      if (r->arg_stk.size)
        /* add it to the group */
        *(re_astarg(r, stk_peek(r, &r->op_stk, 0), 0, 2)) =
            stk_pop(r, &r->arg_stk);
      /* pop the group frame into arg_stk */
      if (stk_push(r, &r->arg_stk, stk_pop(r, &r->op_stk)))
        return ERR_MEM;
    } else { /* push to the arg stk */
      args[0] = ch;
      if (!(res = re_mkast_new(r, CHR, 1, args)) ||
          stk_push(r, &r->arg_stk, res))
        return ERR_MEM;
    }
  }
  if (re_fold(r) || re_fold_alts(r))
    return ERR_MEM;
  if (r->op_stk.size)
    return ERR_PARSE;
  *root = r->arg_stk.size ? stk_pop(r, &r->arg_stk) : REF_NONE;
  return 0;
}

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

#define IMATCH(s, i) ((i) << 1 | (s))
#define IMATCH_S(m) ((m) & 1)
#define IMATCH_I(m) ((m) >> 1)

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
  if (!f->patch_head)
    f->patch_head = f->patch_tail = out_val;
  else {
    patch_set(r, f->patch_tail, out_val);
    f->patch_tail = out_val;
  }
}

void patch_merge(re *r, compframe *p, compframe *q) {
  if (!p->patch_head) {
    p->patch_head = q->patch_head;
    p->patch_tail = q->patch_tail;
    return;
  }
  patch_set(r, p->patch_tail, q->patch_head);
  p->patch_tail = q->patch_tail;
}

void patch_xfer(compframe *dst, compframe *src) {
  dst->patch_head = src->patch_head;
  dst->patch_tail = src->patch_tail;
  src->patch_head = src->patch_tail = REF_NONE;
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
  compframe initial_frame, returned_frame, child_frame;
  u32 set_idx = 0, grp_idx = 0;
  if (!r->prog.size && (stk_push(r, &r->prog, 0) || stk_push(r, &r->prog, 0)))
    return ERR_MEM;
  initial_frame.root_ref = root;
  initial_frame.child_ref = initial_frame.patch_head =
      initial_frame.patch_tail = REF_NONE;
  initial_frame.idx = 0;
  initial_frame.pc = re_prog_size(r);
  if (compframe_push(r, initial_frame))
    return ERR_MEM;
  while (r->comp_stk.size) {
    compframe frame = compframe_pop(r);
    ast_type type;
    u32 args[4], my_pc = re_prog_size(r);
    frame.child_ref = frame.root_ref;
    child_frame.child_ref = child_frame.root_ref = child_frame.patch_head =
        child_frame.patch_tail = REF_NONE;
    type = *re_car(r, frame.root_ref);
    if (!frame.root_ref) {
      /* epsilon */
    } else if (type == CHR) {
      patch(r, &frame, my_pc);
      re_decompast(r, frame.root_ref, 1, args);
      if (re_emit(r, INST(RANGE, 0, br2u(BYTE_RANGE(args[0], args[0])))))
        return ERR_MEM;
      patch_add(r, &frame, my_pc, 0);
    } else if (type == CAT) {
      re_decompast(r, frame.root_ref, 2, args);
      if (frame.idx == 0) {        /* before left child */
        frame.child_ref = args[0]; /* push left child */
        patch_xfer(&child_frame, &frame);
        frame.idx++;
      } else if (frame.idx == 1) { /* after left child */
        frame.child_ref = args[1]; /* push right child */
        patch_xfer(&child_frame, &returned_frame);
        frame.idx++;
      } else if (frame.idx == 2) { /* after right child */
        patch_xfer(&frame, &returned_frame);
      }
    } else if (type == ALT) {
      re_decompast(r, frame.root_ref, 2, args);
      if (frame.idx == 0) { /* before left child */
        patch(r, &frame, frame.pc);
        if (re_emit(r, INST(SPLIT, 0, 0)))
          return ERR_MEM;
        patch_add(r, &child_frame, frame.pc, 0);
        frame.child_ref = args[0], frame.idx++;
      } else if (frame.idx == 1) { /* after left child */
        patch_merge(r, &frame, &returned_frame);
        patch_add(r, &child_frame, frame.pc, 1);
        frame.child_ref = args[1], frame.idx++;
      } else if (frame.idx == 2) { /* after right child */
        patch_merge(r, &frame, &returned_frame);
      }
    } else if (type == QUANT) {
      u32 child, min, max;
      re_decompast(r, frame.root_ref, 3, args);
      child = args[0], min = args[1], max = args[2];
      if (frame.idx < min) { /* before minimum bound */
        patch_xfer(&child_frame, frame.idx ? &returned_frame : &frame);
        frame.child_ref = child;
      } else if (max == INFTY && frame.idx == min) { /* before inf. bound */
        patch(r, frame.idx ? &returned_frame : &frame, my_pc);
        if (re_emit(r, INST(SPLIT, 0, 0)))
          return ERR_MEM;
        patch_add(r, &child_frame, my_pc, 0);
        patch_add(r, &frame, my_pc, 1);
        frame.child_ref = child;
      } else if (max == INFTY && frame.idx == min + 1) { /* after inf. bound */
        patch(r, &returned_frame, frame.pc);
      } else if (frame.idx < max) { /* before maximum bound */
        if (frame.idx == min)
          patch(r, &returned_frame, my_pc);
        if (re_emit(r, INST(SPLIT, 0, 0)))
          return ERR_MEM;
        patch_add(r, &child_frame, my_pc, 0);
        patch_add(r, &frame, my_pc, 1);
        frame.child_ref = child;
      } else if (frame.idx == max) { /* after maximum bound */
        patch_merge(r, &frame, &returned_frame);
      }
      frame.idx++;
    } else if (type == GROUP) {
      u32 child;
      re_decompast(r, frame.root_ref, 2, args);
      child = args[0];
      if (!frame.idx) { /* before child */
        patch(r, &frame, my_pc);
        if (re_emit(r, INST(MATCH, 0, IMATCH(1, 2 * grp_idx++))))
          return ERR_MEM;
        patch_add(r, &child_frame, my_pc, 0);
        frame.child_ref = child, frame.idx++;
      } else if (frame.idx) { /* after child */
        patch(r, &returned_frame, my_pc);
        if (re_emit(r,
                    INST(MATCH, 0,
                         IMATCH(1, IMATCH_I(INST_P(re_prog_get(r, frame.pc))) +
                                       1))))
          return ERR_MEM;
        patch_add(r, &frame, my_pc, 0);
      }
    } else if (type == FORK) {
      re_decompast(r, frame.root_ref, 2, args);
      if (frame.idx == 0) { /* before left child */
        patch(r, &frame, frame.pc);
        if (re_emit(r, INST(SPLIT, 0, 0)))
          return ERR_MEM;
        patch_add(r, &child_frame, frame.pc, 0);
        frame.child_ref = args[0], frame.idx++;
      } else if (frame.idx == 1) { /* after left child */
        if (re_emit(r, INST(MATCH, 0, IMATCH(0, 1 + set_idx++))))
          return ERR_MEM;
        patch(r, &returned_frame, my_pc);
        patch_add(r, &child_frame, frame.pc, 1);
        frame.child_ref = args[1], frame.idx++;
      } else if (frame.idx == 2) { /* after right child */
        patch_xfer(&frame, &returned_frame);
      }
    }
    if (frame.child_ref != frame.root_ref) {
      /* should we push a child? */
      if (compframe_push(r, frame))
        return ERR_MEM;
      child_frame.root_ref = frame.child_ref;
      child_frame.idx = 0;
      child_frame.pc = re_prog_size(r);
      if (compframe_push(r, child_frame))
        return ERR_MEM;
    }
    returned_frame = frame;
  }
  assert(!r->comp_stk.size);
  patch(r, &returned_frame, re_prog_size(r));
  if (re_emit(r, INST(MATCH, 0, IMATCH(0, 1 + set_idx))))
    return ERR_MEM;
  return 0;
}

void re_prog_dump(re *r) {
  u32 i;
  for (i = 0; i < re_prog_size(r); i++) {
    inst ins = re_prog_get(r, i);
    static const char *ops[] = {"RANGE", "ASSRT", "MATCH", "SPLIT"};
    static const int colors[] = {91, 92, 93, 94};
    printf("%04X \x1b[%im%s\x1b[0m %04X %04X\n", i, colors[INST_OP(ins)],
           ops[INST_OP(ins)], INST_N(ins), INST_P(ins));
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

int sset_reset(re *r, sset *s, size_t sz) {
  size_t next_alloc = sz;
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
  s->dense_size = 0;
  s->dense_alloc = next_alloc;
  return 0;
}

void sset_clear(sset *s) { s->dense_size = 0; }

void sset_init(re *r, sset *s) {
  (void)(r);
  s->sparse = NULL;
  s->sparse_alloc = 0;
  s->dense = NULL;
  s->dense_alloc = s->dense_size = 0;
}

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
  s->slots_size = 0, s->last_empty = 0,
  s->per_thrd = per_thrd + 1 /* for refcnt */;
}

u32 save_slots_new(re *r, save_slots *s) {
  u32 out;
  if (!s->per_thrd) {
    out = 1;
  } else {
    if (s->last_empty) {
      /* reclaim */
      out = s->last_empty;
      s->last_empty = s->slots[out * s->per_thrd];
    } else {
      if (s->slots_size + s->per_thrd > s->slots_alloc) {
        /* initial alloc / realloc */
        size_t new_alloc =
            (s->slots_alloc ? s->slots_alloc * 2 : 16) * s->per_thrd;
        size_t *new_slots = re_alloc(r, s->slots_alloc * sizeof(size_t),
                                     new_alloc * sizeof(size_t), s->slots);
        if (!new_slots)
          return 0;
        s->slots = new_slots, s->slots_alloc = new_alloc;
      }
      if (s->slots_size++)
        out = s->slots_size;
      else
        out = save_slots_new(r, s); /* create sentinel 0th */
    }
    memset(s->slots + out * s->per_thrd, 0, sizeof(*s->slots) * s->per_thrd);
  }
  return out;
}

u32 save_slots_fork(save_slots *s, u32 ref) {
  if (s->per_thrd)
    s->slots[ref * s->per_thrd + s->per_thrd - 1]++;
  return ref;
}

void save_slots_kill(save_slots *s, u32 ref) {
  if (!s->per_thrd)
    return;
  if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]--) {
    /* prepend to free list */
    s->slots[ref * s->per_thrd] = s->last_empty;
    s->last_empty = ref;
  }
}

u32 save_slots_set(re *r, save_slots *s, u32 ref, u32 idx, size_t v) {
  u32 out = ref;
  if (!s->per_thrd) {
    /* not saving anything */
    assert(0);
  } else if (v == s->slots[ref * s->per_thrd + idx]) {
    /* not changing anything */
  } else if (!s->slots[ref * s->per_thrd + s->per_thrd - 1]) {
    s->slots[ref * s->per_thrd + idx] = v;
  } else {
    if (!(out = save_slots_new(r, s)))
      return out;
    save_slots_kill(s, ref); /* decrement refcount */
    memcpy(s->slots + out * s->per_thrd, s->slots + ref * s->per_thrd,
           sizeof(*s->slots) * s->per_thrd);
    s->slots[out * s->per_thrd + idx] = v;
  }
  return out;
}

u32 save_slots_perthrd(save_slots *s) {
  return s->per_thrd ? s->per_thrd - 1 : s->per_thrd;
}

u32 save_slots_get(save_slots *s, u32 ref, u32 idx) {
  assert(idx < save_slots_perthrd(s));
  return s->slots[ref * s->per_thrd + idx];
}

typedef struct exec_nfa {
  sset a, b, c;
  stk thrd_stk;
  save_slots slots;
} exec_nfa;

void exec_nfa_init(re *r, exec_nfa *n) {
  sset_init(r, &n->a), sset_init(r, &n->b), sset_init(r, &n->c);
  stk_init(r, &n->thrd_stk);
  save_slots_init(r, &n->slots);
}

void exec_nfa_destroy(re *r, exec_nfa *n) {
  sset_destroy(r, &n->a), sset_destroy(r, &n->b), sset_destroy(r, &n->c);
  stk_destroy(r, &n->thrd_stk);
  save_slots_destroy(r, &n->slots);
}

int exec_nfa_start(re *r, exec_nfa *n, u32 pc, u32 ngrp) {
  thrdspec initial_thrd;
  if (sset_reset(r, &n->a, r->prog.size) ||
      sset_reset(r, &n->b, r->prog.size) || sset_reset(r, &n->c, r->prog.size))
    return ERR_MEM;
  n->thrd_stk.size = 0;
  save_slots_clear(&n->slots, ngrp);
  initial_thrd.pc = pc;
  if (!(initial_thrd.slot = save_slots_new(r, &n->slots)))
    return ERR_MEM;
  sset_add(&n->a, initial_thrd);
  return 0;
}

int thrdstk_push(re *r, stk *s, thrdspec t) {
  return stk_push(r, s, t.pc) || stk_push(r, s, t.slot);
}

thrdspec thrdstk_pop(re *r, stk *s) {
  thrdspec out;
  out.slot = stk_pop(r, s);
  out.pc = stk_pop(r, s);
  return out;
}

int exec_nfa_eps(re *r, exec_nfa *n, size_t pos) {
  size_t i;
  sset_clear(&n->b);
  for (i = 0; i < n->a.dense_size; i++) {
    thrdspec thrd = n->a.dense[i];
    if (thrdstk_push(r, &n->thrd_stk, thrd))
      return ERR_MEM;
    sset_clear(&n->c);
    while (n->thrd_stk.size) {
      thrdspec top = thrdstk_pop(r, &n->thrd_stk);
      inst op = re_prog_get(r, top.pc);
      assert(top.pc);
      if (sset_memb(&n->c, top.pc))
        /* we already processed this thread */
        continue;
      sset_add(&n->c, top);
      switch (INST_OP(re_prog_get(r, top.pc))) {
      case MATCH:
        if (IMATCH_S(INST_P(op))) /* this is a save */ {
          if (IMATCH_I(INST_P(op)) < save_slots_perthrd(&n->slots)) {
            if (!(top.slot = save_slots_set(r, &n->slots, top.slot,
                                            IMATCH_I(INST_P(op)), pos)))
              return ERR_MEM;
          }
          top.pc = INST_N(op);
          if (thrdstk_push(r, &n->thrd_stk, top))
            return ERR_MEM;
          break;
        } /* else fall-through */
      case RANGE:
        sset_add(&n->b, top); /* this is a range or match */
        break;
      case SPLIT: {
        thrdspec pri, sec;
        pri.pc = INST_N(op), pri.slot = top.slot;
        sec.pc = INST_P(op), sec.slot = save_slots_fork(&n->slots, top.slot);
        if (thrdstk_push(r, &n->thrd_stk, pri) ||
            thrdstk_push(r, &n->thrd_stk, sec))
          return ERR_MEM;
        break;
      }
      default:
        assert(0);
      }
    }
  }
  sset_clear(&n->a);
  return 0;
}

int exec_nfa_chr(re *r, exec_nfa *n, unsigned int ch) {
  size_t i;
  for (i = 0; i < n->b.dense_size; i++) {
    thrdspec thrd = n->b.dense[i];
    inst op = re_prog_get(r, thrd.pc);
    switch (INST_OP(op)) {
    case RANGE: {
      byte_range br = u2br(INST_P(op));
      if (ch >= br.l && ch <= br.h) {
        thrd.pc = INST_N(op);
        sset_add(&n->a, thrd);
      } else
        save_slots_kill(&n->slots, thrd.slot);
      break;
    }
    case MATCH: {
      assert(!IMATCH_S(INST_P(op)));
      save_slots_kill(&n->slots, thrd.slot);
      break;
    }
    default:
      assert(0);
    }
  }
  return 0;
}

/* return number of sets matched, -n otherwise */
/* 0th span is the full bounds, 1st is first group, etc. */
int exec_nfa_end(re *r, size_t pos, exec_nfa *n, u32 max_span, u32 max_set,
                 span *out_span, u32 *out_set) {
  size_t i, j, sets = 0;
  if (exec_nfa_eps(r, n, pos))
    return ERR_MEM;
  for (i = 0; i < n->b.dense_size; i++) {
    thrdspec thrd = n->b.dense[i];
    inst op = re_prog_get(r, thrd.pc);
    switch (INST_OP(op)) {
    case RANGE:
      break;
    case MATCH: {
      assert(!IMATCH_S(INST_P(op)));
      if (max_span > 1) {
        assert(save_slots_perthrd(&n->slots) == max_span * 2);
        for (j = 0; j < max_span; j++) {
          out_span[sets * max_span + j].begin =
              save_slots_get(&n->slots, thrd.slot, j);
          out_span[sets * max_span + j].end =
              save_slots_get(&n->slots, thrd.slot, j + 1);
        }
      }
      if (max_set > 0)
        out_set[sets] = IMATCH_I(INST_P(op));
      sets++;
      break;
    }
    default:
      assert(0);
    }
  }
  return sets;
}

int exec_nfa_run(re *r, exec_nfa *n, unsigned int ch, size_t pos) {
  if (exec_nfa_eps(r, n, pos))
    return ERR_MEM;
  return exec_nfa_chr(r, n, ch);
}

/* fully-anchored match: run every character */
/* start-anchored match: run until priority exhaustion */
/* end-anchored match:   run reverse until priority exhaustion */
/* unanchored match:     run dotstar */

int re_match(re *r, const char *s, size_t n, u32 max_span, u32 max_set,
             span *out_span, u32 *out_set, anchor_type anchor) {
  exec_nfa nfa;
  int err = 0;
  size_t i;
  (void)(anchor);
  if (!re_prog_size(r) && (err = re_compile(r, r->ast_root)))
    return err;
  re_ast_dump(r, r->ast_root, 0);
  re_prog_dump(r);
  exec_nfa_init(r, &nfa);
  if ((err = exec_nfa_start(r, &nfa, 1, max_span * 2)))
    goto done;
  for (i = 0; i < n; i++)
    if ((err = exec_nfa_run(r, &nfa, s[i], i)))
      goto done;
  if ((err = exec_nfa_end(r, n, &nfa, max_span, max_set, out_span, out_set)))
    goto done;
done:
  exec_nfa_destroy(r, &nfa);
  return err;
}
