#ifndef BBRE_NIL
  #include "../bbre.c"
#endif

#ifndef BBRE_COV

  #include <stdio.h>

enum dumpformat { TERM, GRAPHVIZ };

static char d_hex(bbre_byte d)
{
  d &= 0xF;
  if (d < 10)
    return '0' + d;
  else
    return 'A' + d - 10;
}

static char *d_chr(char *buf, bbre_uint ch, int ascii)
{
  if ((ch == '\a' && ch == 'a') || (ch == '\b' && ch == 'b') ||
      (ch == '\t' && ch == 't') || (ch == '\n' && ch == 'n') ||
      (ch == '\v' && ch == 'v') || (ch == '\f' && ch == 'f') ||
      (ch == '\r' && ch == 'r'))
    buf[0] = '\\', buf[1] = '\\', buf[2] = ch, buf[3] = 0;
  else if (ch == '"')
    buf[0] = '\\', buf[1] = '"';
  else if (ch >= ' ' && ch < 0x7F)
    buf[0] = ch, buf[1] = 0;
  else if (ascii || (ch < 0x80))
    buf[0] = '\\', buf[1] = '\\', buf[2] = 'x', buf[3] = d_hex(ch >> 4),
    buf[4] = d_hex(ch), buf[5] = 0;
  else
    buf[0] = '\\', buf[1] = '\\', buf[2] = 'u', buf[3] = d_hex(ch >> 20),
    buf[4] = d_hex(ch >> 16), buf[5] = d_hex(ch >> 12), buf[6] = d_hex(ch >> 8),
    buf[7] = d_hex(ch >> 4), buf[8] = d_hex(ch), buf[9] = 0;
  return buf;
}

static char *d_chr_ascii(char *buf, bbre_uint ch) { return d_chr(buf, ch, 1); }

static char *d_chr_unicode(char *buf, bbre_uint ch)
{
  return d_chr(buf, ch, 0);
}

static char *d_assert(char *buf, bbre_assert_flag af)
{
  buf = strcat(buf, af & BBRE_ASSERT_LINE_BEGIN ? "^" : "");
  buf = strcat(buf, af & BBRE_ASSERT_LINE_END ? "$" : "");
  buf = strcat(buf, af & BBRE_ASSERT_TEXT_BEGIN ? "\\\\A" : "");
  buf = strcat(buf, af & BBRE_ASSERT_TEXT_END ? "\\\\z" : "");
  buf = strcat(buf, af & BBRE_ASSERT_WORD ? "\\\\b" : "");
  buf = strcat(buf, af & BBRE_ASSERT_NOT_WORD ? "\\\\B" : "");
  return buf;
}

static char *d_group_flag(char *buf, bbre_group_flag gf, char *pos_neg)
{
  if (gf)
    buf = strcat(buf, pos_neg);
  buf = strcat(buf, gf & BBRE_GROUP_FLAG_INSENSITIVE ? "i" : "");
  buf = strcat(buf, gf & BBRE_GROUP_FLAG_MULTILINE ? "m" : "");
  buf = strcat(buf, gf & BBRE_GROUP_FLAG_DOTNEWLINE ? "s" : "");
  buf = strcat(buf, gf & BBRE_GROUP_FLAG_UNGREEDY ? "U" : "");
  buf = strcat(buf, gf & BBRE_GROUP_FLAG_NONCAPTURING ? ":" : "");
  buf = strcat(buf, gf & BBRE_GROUP_FLAG_EXPRESSION ? "R" : "");
  return buf;
}

static char *d_quant(char *buf, bbre_uint quantval)
{
  if (quantval >= BBRE_INFTY)
    strcat(buf, "\xe2\x88\x9e"); /* infinity symbol */
  else {
    /* macos doesn't have sprintf(), gcc --std=c89 doesn't have snprintf() */
    /* nice! */
    char buf_reverse[32] = {0}, buf_fwd[32] = {0};
    int i = 0, j = 0;
    do {
      buf_reverse[i++] = quantval % 10 + '0';
      quantval /= 10;
    } while (quantval);
    while (i)
      buf_fwd[j++] = buf_reverse[--i];
    strcat(buf, buf_fwd);
  }
  return buf;
}

void d_ast_i(bbre *r, bbre_uint root, bbre_uint ilvl, int format)
{
  const char *colors[] = {"1", "2", "3", "4"};
  bbre_uint i, first = root ? *bbre_ast_type_ref(r, root) : 0;
  bbre_uint sub[2] = {0xFF, 0xFF};
  char buf[32] = {0}, buf2[32] = {0};
  const char *node_name =
      root == BBRE_NIL                      ? "\xc9\x9b" /* epsilon */
      : (first == BBRE_AST_TYPE_CHR)        ? "CHR"
      : (first == BBRE_AST_TYPE_CAT)        ? (sub[0] = 0, sub[1] = 1, "CAT")
      : (first == BBRE_AST_TYPE_ALT)        ? (sub[0] = 0, sub[1] = 1, "ALT")
      : (first == BBRE_AST_TYPE_QUANT)      ? (sub[0] = 0, "QUANT")
      : (first == BBRE_AST_TYPE_UQUANT)     ? (sub[0] = 0, "UQUANT")
      : (first == BBRE_AST_TYPE_GROUP)      ? (sub[0] = 0, "GROUP")
      : (first == BBRE_AST_TYPE_IGROUP)     ? (sub[0] = 0, "IGROUP")
      : (first == BBRE_AST_TYPE_CC_LEAF)    ? "CC_LEAF"
      : (first == BBRE_AST_TYPE_CC_BUILTIN) ? "CC_BUILTIN"
      : (first == BBRE_AST_TYPE_CC_NOT)     ? (sub[0] = 0, "CC_NOT")
      : (first == BBRE_AST_TYPE_CC_OR)      ? (sub[0] = 0, sub[1] = 1, "CC_OR")
      : (first == BBRE_AST_TYPE_ANYCHAR)    ? ("ANYCHAR")
      : (first == BBRE_AST_TYPE_ANYBYTE)
          ? "ANYBYTE"
          : /* (first == BBRE_AST_TYPE_ASSERT) */ "ASSERT";
  assert(node_name != NULL);
  if (format == TERM) {
    printf("%04u ", root);
    for (i = 0; i < ilvl; i++)
      printf(" ");
    printf("%s ", node_name);
  } else if (format == GRAPHVIZ) {
    printf("A%04X [label=\"%s\\n", root, node_name);
  }
  if (first == BBRE_AST_TYPE_CHR)
    printf("%s", d_chr_unicode(buf, *bbre_ast_param_ref(r, root, 0)));
  else if (first == BBRE_AST_TYPE_GROUP)
    printf(
        "%s/%s/%u", d_group_flag(buf, *bbre_ast_param_ref(r, root, 1), "+"),
        d_group_flag(buf, *bbre_ast_param_ref(r, root, 2), "-"),
        *bbre_ast_param_ref(r, root, 3));
  else if (first == BBRE_AST_TYPE_IGROUP)
    printf(
        "%s/%s", d_group_flag(buf, *bbre_ast_param_ref(r, root, 1), "+"),
        d_group_flag(buf, *bbre_ast_param_ref(r, root, 2), "-"));
  else if (first == BBRE_AST_TYPE_QUANT || first == BBRE_AST_TYPE_UQUANT)
    printf(
        "%s-%s", d_quant(buf, *bbre_ast_param_ref(r, root, 1)),
        d_quant(buf2, *bbre_ast_param_ref(r, root, 2)));
  else if (first == BBRE_AST_TYPE_CC_LEAF)
    printf(
        "%s-%s", d_chr_unicode(buf, *bbre_ast_param_ref(r, root, 0)),
        d_chr_unicode(buf2, *bbre_ast_param_ref(r, root, 1)));
  else if (first == BBRE_AST_TYPE_CC_BUILTIN)
    printf(
        "%i/%i", *bbre_ast_param_ref(r, root, 0),
        *bbre_ast_param_ref(r, root, 1));
  else if (first == BBRE_AST_TYPE_ASSERT)
    printf("%s", d_assert(buf, *bbre_ast_param_ref(r, root, 0)));
  if (format == GRAPHVIZ)
    printf(
        "\"]\nsubgraph cluster_%04X { "
        "label=\"\";style=filled;colorscheme=greys7;fillcolor=%s;",
        root, colors[ilvl % (sizeof(colors) / sizeof(*colors))]);
  if (format == TERM)
    printf("\n");
  for (i = 0; i < sizeof(sub) / sizeof(*sub); i++)
    if (sub[i] != 0xFF) {
      bbre_uint child = *bbre_ast_param_ref(r, root, sub[i]);
      d_ast_i(r, child, ilvl + 1, format);
      if (format == GRAPHVIZ)
        printf(
            "A%04X -> A%04X [style=%s]\n", root, child, i ? "dashed" : "solid");
    }
  if (format == GRAPHVIZ)
    printf("}\n");
}

void d_ast(bbre *r) { d_ast_i(r, r->ast_root, 0, TERM); }

void d_ast_gv(bbre *r) { d_ast_i(r, r->ast_root, 0, GRAPHVIZ); }

void d_op_stk(bbre *r)
{
  bbre_uint i;
  printf("%lu:\n", bbre_buf_size(r->op_stk));
  for (i = 0; i < bbre_buf_size(r->op_stk); i++) {
    printf("%u\n", r->op_stk[i]);
  }
}

void d_sset(bbre_sset *s)
{
  bbre_uint i;
  for (i = 0; i < s->dense_size; i++)
    printf("%04X pc: %04X slot: %04X\n", i, s->dense[i].pc, s->dense[i].slot);
}

void d_prog_range(
    const bbre_prog *prog, bbre_uint start, bbre_uint end, int format)
{
  bbre_uint j, k;
  assert(end <= bbre_prog_size(prog));
  if (format == GRAPHVIZ)
    printf("node [colorscheme=pastel16]\n");
  for (; start < end; start++) {
    bbre_inst ins = bbre_prog_get(prog, start);
    static const char *ops[] = {"RANGE", "SPLIT", "MATCH", "ASSRT"};
    static const char *labels[] = {"F  ", "R  ", "F.*", "R.*", "   ", "+  "};
    char start_buf[10] = {0}, end_buf[10] = {0}, assert_buf[32] = {0};
    k = 4;
    for (j = 0; j < 4; j++)
      if (start == prog->entry[j])
        k = k == 4 ? j : 5;
    if (format == TERM) {
      static const int colors[] = {91, 94, 93, 92};
      printf(
          "%04X %01X \x1b[%im%s\x1b[0m \x1b[%im%04X\x1b[0m \x1b[%im%04X\x1b[0m "
          "%s",
          start, prog->set_idxs[start], colors[bbre_inst_opcode(ins)],
          ops[bbre_inst_opcode(ins)],
          bbre_inst_next(ins) ? (bbre_inst_next(ins) == start + 1 ? 90 : 0)
                              : 91,
          bbre_inst_next(ins),
          (bbre_inst_opcode(ins) == BBRE_OPCODE_SPLIT)
              ? (bbre_inst_param(ins) == start + 1
                     ? 90
                     : (bbre_inst_param(ins) ? 0 : 90))
              : 0,
          bbre_inst_param(ins), labels[k]);
      if (bbre_inst_opcode(ins) == BBRE_OPCODE_MATCH)
        printf(
            " %u %s", bbre_inst_match_param_idx(bbre_inst_param(ins)),
            bbre_inst_match_param_end(bbre_inst_param(ins)) ? "end" : "begin");
      printf("\n");
    } else {
      static const char *shapes[] = {"box", "oval", "pentagon", "diamond"};
      static const int colors[] = {1, 2, 6, 3};
      printf(
          "I%04X "
          "[shape=%s,fillcolor=%i,style=filled,regular=false,forcelabels=true,"
          "xlabel=\"%u\","
          "label=\"%s\\n",
          start, shapes[bbre_inst_opcode(ins)], colors[bbre_inst_opcode(ins)],
          start, ops[bbre_inst_opcode(ins)]);
      if (bbre_inst_opcode(ins) == BBRE_OPCODE_RANGE)
        printf(
            "%s-%s",
            d_chr_ascii(
                start_buf, bbre_uint_to_byte_range(bbre_inst_param(ins)).l),
            d_chr_ascii(
                end_buf, bbre_uint_to_byte_range(bbre_inst_param(ins)).h));
      else if (bbre_inst_opcode(ins) == BBRE_OPCODE_MATCH)
        printf(
            "%u %s", bbre_inst_match_param_idx(bbre_inst_param(ins)),
            bbre_inst_match_param_end(bbre_inst_param(ins)) ? "end" : "begin");
      else if (bbre_inst_opcode(ins) == BBRE_OPCODE_ASSERT)
        printf("%s", d_assert(assert_buf, bbre_inst_param(ins)));
      printf("\"]\n");
      if (!(bbre_inst_opcode(ins) == BBRE_OPCODE_MATCH &&
            !bbre_inst_next(ins))) {
        printf("I%04X -> I%04X\n", start, bbre_inst_next(ins));
        if (bbre_inst_opcode(ins) == BBRE_OPCODE_SPLIT)
          printf(
              "I%04X -> I%04X [style=dashed]\n", start, bbre_inst_param(ins));
      }
    }
  }
}

void d_prog(const bbre_prog *prog)
{
  d_prog_range(prog, 1, prog->entry[BBRE_PROG_ENTRY_REVERSE], TERM);
}

void d_prog_r(const bbre_prog *prog)
{
  d_prog_range(
      prog, prog->entry[BBRE_PROG_ENTRY_REVERSE], bbre_prog_size(prog), TERM);
}

void d_prog_whole(const bbre_prog *prog)
{
  d_prog_range(prog, 0, bbre_prog_size(prog), TERM);
}

void d_prog_gv(const bbre_prog *prog)
{
  d_prog_range(prog, 1, prog->entry[BBRE_PROG_ENTRY_DOTSTAR], GRAPHVIZ);
}

void d_prog_gv_re(bbre *reg) { d_prog_gv(&reg->prog); }

void d_cctree_i(
    const bbre_buf(bbre_compcc_tree) cc_tree, bbre_uint ref, bbre_uint lvl)
{
  bbre_uint i;
  const bbre_compcc_tree *node = cc_tree + ref;
  printf("%04X [%08X] ", ref, node->aux.pc);
  for (i = 0; i < lvl; i++)
    printf("  ");
  printf(
      "%02X-%02X\n", bbre_uint_to_byte_range(node->range).l,
      bbre_uint_to_byte_range(node->range).h);
  if (node->child_ref)
    d_cctree_i(cc_tree, node->child_ref, lvl + 1);
  if (node->sibling_ref)
    d_cctree_i(cc_tree, node->sibling_ref, lvl);
}

void d_cctree(const bbre_buf(bbre_compcc_tree) cc_tree, bbre_uint ref)
{
  d_cctree_i(cc_tree, ref, 0);
}
#endif
