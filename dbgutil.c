#ifndef MN_RE_H
#include "re.c"
#endif

void astdump_i(re *r, u32 root, u32 ilvl) {
  u32 i, first = r->ast[root].v, rest = r->ast[root + 1].v;
  printf("%04u ", root);
  for (i = 0; i < ilvl; i++)
    printf(" ");
  if (root == REF_NONE) {
    printf("<eps>\n");
  } else if (first == REG) {
    printf("REG\n");
    astdump_i(r, *re_astarg(r, root, 0, 1), ilvl + 1);
  } else if (first == CHR) {
    printf("CHR %02X\n", rest);
  } else if (first == CAT) {
    printf("CAT\n");
    astdump_i(r, *re_astarg(r, root, 0, 2), ilvl + 1);
    astdump_i(r, *re_astarg(r, root, 1, 2), ilvl + 1);
  } else if (first == ALT) {
    printf("ALT\n");
    astdump_i(r, *re_astarg(r, root, 0, 2), ilvl + 1);
    astdump_i(r, *re_astarg(r, root, 1, 2), ilvl + 1);
  } else if (first == GROUP) {
    printf("GRP flag=%u\n", *re_astarg(r, root, 1, 2));
    astdump_i(r, *re_astarg(r, root, 0, 2), ilvl + 1);
  } else if (first == QUANT) {
    printf("QNT min=%u max=%u\n", *re_astarg(r, root, 1, 3),
           *re_astarg(r, root, 2, 3));
    astdump_i(r, *re_astarg(r, root, 0, 3), ilvl + 1);
  } else if (first == CLS) {
    printf("CLS min=%02X max=%02X\n", *re_astarg(r, root, 0, 3),
           *re_astarg(r, root, 1, 3));
    astdump_i(r, *re_astarg(r, root, 2, 3), ilvl + 1);
  } else if (first == ICLS) {
    printf("ICLS min=%02X max=%02X\n", *re_astarg(r, root, 0, 3),
           *re_astarg(r, root, 1, 3));
    astdump_i(r, *re_astarg(r, root, 2, 3), ilvl + 1);
  }
}

void astdump(re *r, u32 root) { astdump_i(r, root, 0); }

void progdump(re *r) {
  u32 i, j, k;
  for (i = 0; i < re_prog_size(r); i++) {
    inst ins = re_prog_get(r, i);
    static const char *ops[] = {"RANGE", "ASSRT", "MATCH", "SPLIT"};
    static const int colors[] = {91, 92, 93, 94};
    static const char *labels[] = {"F  ", "R  ", "F.*", "R.*", "   ", "+  "};
    k = 4;
    for (j = 0; j < 4; j++) {
      if (i == r->entry[j]) {
        k = k == 4 ? j : 5;
      }
    }
    printf("%04X \x1b[%im%s\x1b[0m %04X %04X %s", i, colors[INST_OP(ins)],
           ops[INST_OP(ins)], INST_N(ins), INST_P(ins), labels[k]);
    if (INST_OP(ins) == MATCH) {
      printf(" %c/%u", IMATCH_S(INST_P(ins)) ? 'G' : 'E',
             IMATCH_I(INST_P(ins)));
    }
    printf("\n");
  }
}

void cctreedump_i(stk *cc_tree, u32 ref, u32 lvl) {
  u32 i;
  compcc_node *node = cc_treeref(cc_tree, ref);
  printf("%04X [%08X] ", ref, node->hash);
  for (i = 0; i < lvl; i++)
    printf("  ");
  printf("%02X-%02X\n", u2br(node->range).l, u2br(node->range).h);
  if (node->child_ref)
    cctreedump_i(cc_tree, node->child_ref, lvl + 1);
  if (node->sibling_ref)
    cctreedump_i(cc_tree, node->sibling_ref, lvl);
}

void cctreedump(stk *cc_tree, u32 ref) { cctreedump_i(cc_tree, ref, 0); }
