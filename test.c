#include <stdio.h>
#include <string.h>

/* unfinished: parse string ends early
 * malformed:  parse string contains a malformed utf-8 sequence
 * invalid:    parse string is valid utf-8 but contains an unexpected char */

#include "mptest.h"

#include "re.h"

#ifdef TEST_BULK
  #define TEST_NAMED_CLASS_RANGE_MAX 0x110000
#elif RE_COV
  /* to ensure the OOM checker doesn't take a long-ass time */
  #define TEST_NAMED_CLASS_RANGE_MAX 0x1
#else
  #define TEST_NAMED_CLASS_RANGE_MAX 0x80
#endif

#define IMPLIES(c, pred) (!(c) || (pred))

size_t utf_encode(char *out_buf, u32 codep)
{
  if (codep <= 0x7F) {
    out_buf[0] = codep & 0x7F;
    return 1;
  } else if (codep <= 0x07FF) {
    out_buf[0] = (u8)(((codep >> 6) & 0x1F) | 0xC0);
    out_buf[1] = (u8)(((codep >> 0) & 0x3F) | 0x80);
    return 2;
  } else if (codep <= 0xFFFF) {
    out_buf[0] = (u8)(((codep >> 12) & 0x0F) | 0xE0);
    out_buf[1] = (u8)(((codep >> 6) & 0x3F) | 0x80);
    out_buf[2] = (u8)(((codep >> 0) & 0x3F) | 0x80);
    return 3;
  } else if (codep <= 0x10FFFF) {
    out_buf[0] = (u8)(((codep >> 18) & 0x07) | 0xF0);
    out_buf[1] = (u8)(((codep >> 12) & 0x3F) | 0x80);
    out_buf[2] = (u8)(((codep >> 6) & 0x3F) | 0x80);
    out_buf[3] = (u8)(((codep >> 0) & 0x3F) | 0x80);
    return 4;
  } else {
    assert(0);
    return 0;
  }
}

#define TEST_MAX_SPAN 10
#define TEST_MAX_SET  10

int check_match_results(
    re *r, re_exec *e, const char *s, size_t n, u32 max_span, u32 max_set,
    anchor_type anchor, span *check_span, u32 *check_set, u32 check_nsets)
{
  int err;
  /* memory for found spans and found sets */
  span found_span[TEST_MAX_SPAN * TEST_MAX_SET];
  u32 found_set[TEST_MAX_SET], sets_to_check;
  u32 i, j;
  /* perform the match */
  assert(e);
  if ((err = re_exec_match(
           e, s, n, max_span, max_set, found_span, found_set, anchor)) ==
      ERR_MEM)
    goto oom_re;
  ASSERT_GTEm(err, 0, "re_match() returned an error");
  ASSERT_EQm(
      (u32)err, check_nsets,
      "re_match() didn't match the correct number of sets");
  /* we only actually need to check a subset of the sets matched, according to
   * the `check_nsets` parameter. also, in the case of boolean matches, max_set
   * will be zero and check_nsets will be 1. */
  sets_to_check = (check_nsets > max_set ? max_set : check_nsets);
  /* check all output spans and sets for agreement with the test case */
  for (i = 0; i < sets_to_check; i++) {
    if (check_set)
      ASSERT_EQm(check_set[i], found_set[i], "found unexpected set index");
    for (j = 0; j < max_span; j++) {
      ASSERT_EQm(
          check_span[i * max_span + j].begin,
          found_span[i * max_span + j].begin,
          "found unexpected span beginning");
      ASSERT_EQm(
          check_span[i * max_span + j].end, found_span[i * max_span + j].end,
          "found unexpected span end");
    }
  }
  PASS();
oom_re:
  re_exec_destroy(e);
  re_destroy(r);
  OOM();
}

int check_matches_n(
    const char **regexes, size_t *regex_n, u32 nregex, const char *s, size_t n,
    u32 max_span, u32 max_set, anchor_type anchor, span *check_span,
    u32 *check_set, u32 check_nsets)
{
  re *r = NULL;
  re_exec *e = NULL;
  int err;
  u32 i;
  ASSERT_LTEm(nregex, TEST_MAX_SET, "too many regexes to match");
  ASSERT_LTEm(max_span, TEST_MAX_SPAN, "too many spans to match");
  ASSERT_LTEm(max_set, TEST_MAX_SET, "too many sets to match");
  /* initialize the regex: use argument to init_full() if there's only one
   * regex, otherwise union all input regexes */
  if ((err = re_init_full(
           &r, nregex == 1 ? *regexes : NULL, nregex == 1 ? regex_n[0] : 0,
           NULL)) == ERR_MEM)
    goto oom_re;
  ASSERT_EQm(err, 0, "re_init_full() returned a nonzero value");
  for (i = 0; i < nregex && nregex != 1; i++) {
    if ((err = re_union(r, regexes[i], regex_n[i])) == ERR_MEM)
      goto oom_re;
    ASSERT_EQm(err, 0, "re_union() returned a nonzero value");
  }
  if ((err = re_compile(r)) == ERR_MEM)
    goto oom_re;
  ASSERT_EQm(err, 0, "re_compile() returned a nonzero value");
  if ((err = re_exec_init(r, &e)))
    goto oom_re;
  ASSERT_EQm(err, 0, "re_exec_init() returned a nonzero value");
  PROPAGATE(check_match_results(
      r, e, s, n, max_span, max_set, anchor, check_span, check_set,
      check_nsets));
  /* check to make sure that all match modes agree */
  /* if `check_nsets` > 0, then a boolean match *must* return 1.
   * if `check_nsets` == 0, then a boolean match *must* return 0. */
  PROPAGATE(
      check_match_results(r, e, s, n, 0, 0, anchor, NULL, NULL, !!check_nsets));
  if (anchor == 'B' && !max_span) {
    /* if we're fully anchored, group 0 *must* be the bounds of the match */
    span check_span_anchored[TEST_MAX_SET];
    for (i = 0; i < check_nsets; i++)
      check_span_anchored[i].begin = 0, check_span_anchored[i].end = n;
    PROPAGATE(check_match_results(
        r, e, s, n, 1, max_set, anchor, check_span_anchored, check_set,
        check_nsets));
  }
  if (1) {
    /* start with just bounds */
    span found_span[TEST_MAX_SPAN * TEST_MAX_SET];
    u32 found_set[TEST_MAX_SET], idx;
    err =
        re_exec_match(e, s, n, 1, TEST_MAX_SET, found_span, found_set, anchor);
    if (err == ERR_MEM)
      goto oom_re;
    ASSERT_GTE(err, 0);
    for (idx = 0; idx < (unsigned)err; idx++) {
      re *r2;
      int err2;
      span found_span_2[1];
      u32 found_set_2[1];
      if ((err2 = re_init_full(
               &r2, regexes[found_set[idx]], regex_n[found_set[idx]], NULL)) ==
          ERR_MEM)
        goto oom_re2;
      ASSERT_EQm(err2, 0, "re_init_full() returned nonzero value");
      if ((err2 = re_compile(r2)) == ERR_MEM)
        goto oom_re2;
      ASSERT_EQm(err2, 0, "re_compile() returned nonzero value");
      /* both anchors */
      if ((err2 = re_match(r2, s, n, 1, 1, found_span_2, found_set_2, 'B')) ==
          ERR_MEM)
        goto oom_re2;
      ASSERT_GTE(err2, 0);
      if (err2 == 1) {
        ASSERT_EQ(found_set_2[0], 0);
        ASSERT_EQ(found_span_2[0].begin, 0);
        ASSERT_EQ(found_span_2[0].end, n);
      }
      if (anchor == 'B') {
        ASSERT_EQ(err2, 1);
        ASSERT_EQ(found_span_2[0].begin, found_span[idx].begin);
        ASSERT_EQ(found_span_2[0].end, found_span[idx].end);
      }
      /* start anchored */
      if ((err2 = re_match(r2, s, n, 1, 1, found_span_2, found_set_2, 'S')) ==
          ERR_MEM)
        goto oom_re2;
      if (err2 == 1) {
        ASSERT_EQ(found_span_2[0].begin, 0);
        ASSERT_EQ(found_set_2[0], 0);
      }
      if (anchor == 'S') {
        ASSERT_EQ(err2, 1);
        ASSERT_EQ(found_span_2[0].begin, found_span[idx].begin);
        ASSERT_EQ(found_span_2[0].end, found_span[idx].end);
        ASSERT_EQ(found_set_2[0], 0);
      }
      /* end anchored */
      if ((err2 = re_match(r2, s, n, 1, 1, found_span_2, found_set_2, 'E')) ==
          ERR_MEM)
        goto oom_re2;
      if (err2 == 1) {
        ASSERT_EQ(found_span_2[0].end, n);
        ASSERT_EQ(found_set_2[0], 0);
      }
      if (anchor == 'E') {
        ASSERT_EQ(err2, 1);
        ASSERT_EQ(found_span_2[0].begin, found_span[idx].begin);
        ASSERT_EQ(found_span_2[0].end, found_span[idx].end);
      }
      /* unanchored */
      if ((err2 = re_match(r2, s, n, 1, 1, found_span_2, found_set_2, 'U')) ==
          ERR_MEM)
        goto oom_re2;
      if (err2 == 1) {
        ASSERT_EQ(found_set_2[0], 0);
      }
      if (anchor == 'U') {
        ASSERT_EQ(err2, 1);
        ASSERT_EQ(found_span_2[0].begin, found_span[idx].begin);
        ASSERT_EQ(found_span_2[0].end, found_span[idx].end);
      }
      re_destroy(r2);
      continue;
    oom_re2:
      re_destroy(r2);
      goto oom_re;
    }
  }
  re_exec_destroy(e);
  re_destroy(r);
  PASS();
oom_re:
  re_exec_destroy(e);
  re_destroy(r);
  OOM();
}

int check_match(
    const char *regex, const char *s, size_t n, u32 max_span, u32 max_set,
    anchor_type anchor, span *check_span, u32 *check_set, u32 check_nsets)
{
  size_t regex_n = strlen(regex);
  return check_matches_n(
      &regex, &regex_n, 1, s, n, max_span, max_set, anchor, check_span,
      check_set, check_nsets);
}

int check_fullmatch_n(const char *regex, const char *s, size_t n)
{
  return check_match(regex, s, n, 0, 0, A_BOTH, NULL, NULL, 1);
}

int check_not_fullmatch_n(const char *regex, const char *s, size_t n)
{
  return check_match(regex, s, n, 0, 0, A_BOTH, NULL, NULL, 0);
}

int check_fullmatch(const char *regex, const char *s)
{
  return check_fullmatch_n(regex, s, strlen(s));
}

int check_not_fullmatch(const char *regex, const char *s)
{
  return check_not_fullmatch_n(regex, s, strlen(s));
}

int check_match_g1_a(
    const char *regex, const char *s, size_t b, size_t e, anchor_type anchor)
{
  span g;
  g.begin = b, g.end = e;
  return check_match(regex, s, strlen(s), 1, 1, anchor, &g, NULL, 1);
}

int check_match_g2_a(
    const char *regex, const char *s, size_t b, size_t e, size_t b2, size_t e2,
    anchor_type anchor)
{
  span g[2];
  g[0].begin = b, g[0].end = e;
  g[1].begin = b2, g[1].end = e2;
  return check_match(regex, s, strlen(s), 2, 1, anchor, g, NULL, 1);
}

int check_match_s2_a(
    const char *r1, const char *r2, const char *s, anchor_type anchor)
{
  u32 set[2] = {0, 1};
  const char *regexes[2];
  size_t regexes_n[2];
  regexes[0] = r1, regexes[1] = r2;
  regexes_n[0] = strlen(r1), regexes_n[1] = strlen(r2);
  return check_matches_n(
      regexes, regexes_n, 2, s, strlen(s), 0, 2, anchor, NULL, set, 2);
}

int check_match_s2_g1_a(
    const char *r1, const char *r2, const char *s, size_t b11, size_t e11,
    size_t b21, size_t e21, anchor_type anchor)
{
  u32 set[2] = {0, 1};
  span g[2];
  const char *regexes[2];
  size_t regexes_n[2];
  regexes[0] = r1, regexes[1] = r2;
  regexes_n[0] = strlen(r1), regexes_n[1] = strlen(r2);
  g[0].begin = b11, g[0].end = e11;
  g[1].begin = b21, g[1].end = e21;
  return check_matches_n(
      regexes, regexes_n, 2, s, strlen(s), 1, 2, anchor, g, set, 2);
}

int check_match_s2_g2_a(
    const char *r1, const char *r2, const char *s, size_t b11, size_t e11,
    size_t b12, size_t e12, size_t b21, size_t e21, size_t b22, size_t e22,
    anchor_type anchor)
{
  u32 set[2] = {0, 1};
  span g[4];
  const char *regexes[2];
  size_t regexes_n[2];
  regexes[0] = r1, regexes[1] = r2;
  regexes_n[0] = strlen(r1), regexes_n[1] = strlen(r2);
  g[0].begin = b11, g[0].end = e11;
  g[1].begin = b12, g[1].end = e12;
  g[2].begin = b21, g[2].end = e21;
  g[3].begin = b22, g[3].end = e22;
  return check_matches_n(
      regexes, regexes_n, 2, s, strlen(s), 2, 2, anchor, g, set, 2);
}

#define ASSERT_MATCH(regex, str)  PROPAGATE(check_fullmatch(regex, str))
#define ASSERT_NMATCH(regex, str) PROPAGATE(check_not_fullmatch(regex, str))
#define ASSERT_MATCH_N(regex, str, sz)                                         \
  PROPAGATE(check_fullmatch_n(regex, str, sz));
#define ASSERT_NMATCH_N(regex, str, sz)                                        \
  PROPAGATE(check_not_fullmatch_n(regex, str, sz));
#define ASSERT_MATCH_G1_A(regex, str, b, e, anchor)                            \
  PROPAGATE(check_match_g1_a(regex, str, b, e, anchor))
#define ASSERT_MATCH_G1(regex, str, b, e)                                      \
  ASSERT_MATCH_G1_A(regex, str, b, e, A_BOTH)
#define ASSERT_MATCH_G2_A(regex, str, b, e, b2, e2, anchor)                    \
  PROPAGATE(check_match_g2_a(regex, str, b, e, b2, e2, anchor))
#define ASSERT_MATCH_G2(regex, str, b, e, b2, e2)                              \
  ASSERT_MATCH_G2_A(regex, str, b, e, b2, e2, A_BOTH)
#define ASSERT_MATCH_S2(r1, r2, str)                                           \
  PROPAGATE(check_match_s2_a(r1, r2, str, A_BOTH))
#define ASSERT_MATCH_S2_G1(r1, r2, str, b11, e11, b21, e21)                    \
  PROPAGATE(check_match_s2_g1_a(r1, r2, str, b11, e11, b21, e21, A_BOTH))
#define ASSERT_MATCH_S2_G2(                                                    \
    r1, r2, str, b11, e11, b12, e12, b21, e21, b22, e22)                       \
  PROPAGATE(check_match_s2_g2_a(                                               \
      r1, r2, str, b11, e11, b12, e12, b21, e21, b22, e22, A_BOTH))

#define ASSERT_MATCH_ONLY(regex, str) ASSERT_MATCH(regex, str)

int check_noparse_n(const char *regex, size_t n)
{
  re *r;
  int err;
  if ((err = re_init_full(&r, regex, n, NULL)) == ERR_MEM)
    goto oom;
  ASSERT_EQ(err, ERR_PARSE);
  re_destroy(r);
  PASS();
oom:
  re_destroy(r);
  OOM();
}

int check_noparse(const char *regex)
{
  PROPAGATE(check_noparse_n(regex, strlen(regex)));
  PASS();
}

#define ASSERT_NOPARSE(regex) PROPAGATE(check_noparse(regex))

int check_compiles_n(const char *regex, size_t n)
{
  re *r;
  int err;
  if ((err = re_init_full(&r, regex, n, NULL)) == ERR_MEM)
    goto oom;
  ASSERT_EQ(err, 0);
  if ((err = re_match(r, "", 0, 0, 0, NULL, NULL, 'U')) == ERR_MEM)
    goto oom;
  re_destroy(r);
  PASS();
oom:
  re_destroy(r);
  OOM();
}

int check_compiles(const char *regex)
{
  PROPAGATE(check_compiles_n(regex, strlen(regex)));
  PASS();
}

typedef struct rrange {
  u32 lo, hi;
} rrange;

u32 matchnum(const char *num)
{
  u32 out = 0;
  unsigned char chout;
  if (sscanf(num, "0x%X", &out))
    return out;
  else if (sscanf(num, "%c", &chout))
    return chout;
  else
    assert(0);
  return 0;
}

u32 matchspec(const char *spec, rrange *ranges)
{
  u32 n = 0;
  while (*spec) {
    const char *comma = strchr(spec, ',');
    const char *nextspec = comma ? comma + 1 : comma;
    const char *space = strchr(spec, ' ');
    char tmp_buf[16];
    if (!comma)
      comma = spec + strlen(spec), nextspec = comma;
    if (!space || space > comma)
      space = comma;
    memset(tmp_buf, 0, sizeof tmp_buf);
    memcpy(tmp_buf, spec, space - spec);
    ranges->lo = ranges->hi = matchnum(tmp_buf);
    if (space < comma) {
      memset(tmp_buf, 0, sizeof tmp_buf);
      memcpy(tmp_buf, space + 1, comma - space);
      ranges->hi = matchnum(tmp_buf);
    }
    spec = nextspec, ranges++, n++;
  }
  return n;
}

int assert_cc_match(const char *regex, const char *spec, int invert)
{
  re *r;
  int err;
  u32 codep;
  char utf8[16];
  rrange ranges[64];
  u32 num_ranges = matchspec(spec, ranges), range_idx;
  re_exec *exec = NULL;
  if ((err = re_init_full(&r, regex, strlen(regex), NULL)) == ERR_MEM)
    goto oom;
  ASSERT(!err);
  if ((err = re_compile(r)) == ERR_MEM)
    goto oom;
  ASSERT(!err);
  if ((err = re_exec_init(r, &exec)) == ERR_MEM)
    goto oom;
  ASSERT(!err);
  for (codep = 0; codep < TEST_NAMED_CLASS_RANGE_MAX; codep++) {
    size_t sz = utf_encode(utf8, codep);
    if ((err = re_exec_match(exec, utf8, sz, 0, 0, NULL, NULL, A_BOTH)) ==
        ERR_MEM)
      goto oom;
    for (range_idx = 0; range_idx < num_ranges; range_idx++) {
      if (codep >= ranges[range_idx].lo && codep <= ranges[range_idx].hi) {
        ASSERT_EQ(err, !invert);
        break;
      }
    }
    if (range_idx == num_ranges) {
      if ((err = re_exec_match(exec, utf8, sz, 0, 0, NULL, NULL, A_BOTH)) ==
          ERR_MEM)
        goto oom;
      ASSERT_EQ(err, invert);
    }
  }
  re_exec_destroy(exec);
  re_destroy(r);
  PASS();
oom:
  re_exec_destroy(exec);
  re_destroy(r);
  OOM();
}

#define ASSERT_CC_MATCH(regex, spec) PROPAGATE(assert_cc_match(regex, spec, 0))

TEST(init_empty)
{
  /* init should initialize the regular expression or return NULL on OOM */
  re *r = re_init("");
  if (!r)
    OOM();
  re_destroy(r);
  PASS();
}

TEST(init_some)
{
  re *r = re_init("a");
  if (!r)
    OOM();
  re_destroy(r);
  PASS();
}

extern void *re_default_alloc(size_t prev, size_t next, void *ptr);

TEST(init_full_default_alloc)
{
  re *r;
  int err = re_init_full(&r, "abc", 3, re_default_alloc);
  re_destroy(r);
  if (err == ERR_MEM)
    OOM();
  ASSERT_EQ(err, 0);
  return err;
}

/*
currently, we have no way of differentiating between a parse error and OOM
TEST(init_bad)
{
  re *r = re_init("\xff");
  if (!r)
    OOM();
  PASS();
}
*/

SUITE(init)
{
  RUN_TEST(init_empty);
  RUN_TEST(init_some);
  /*RUN_TEST(init_bad);*/
  RUN_TEST(init_full_default_alloc);
}

TEST(chr_1)
{
  ASSERT_MATCH_ONLY("a", "a");
  PASS();
}

TEST(chr_2)
{
  ASSERT_MATCH_ONLY("\xd4\x80", "\xd4\x80");
  PASS();
}

TEST(chr_3)
{
  ASSERT_MATCH_ONLY("\xe2\x98\x85", "\xe2\x98\x85");
  PASS();
}

TEST(chr_4)
{
  ASSERT_MATCH_ONLY("\xf0\x9f\xa4\xa0", "\xf0\x9f\xa4\xa0");
  PASS();
}

TEST(chr_malformed)
{
  ASSERT_NOPARSE("\xff");
  PASS();
}

SUITE(chr)
{
  RUN_TEST(chr_1);
  RUN_TEST(chr_2);
  RUN_TEST(chr_3);
  RUN_TEST(chr_4);
  RUN_TEST(chr_malformed);
}

TEST(cat_single)
{
  ASSERT_MATCH_ONLY("ab", "ab");
  PASS();
}

TEST(cat_double)
{
  ASSERT_MATCH_ONLY("abc", "abc");
  PASS();
}

SUITE(cat)
{
  RUN_TEST(cat_single);
  RUN_TEST(cat_double);
}

TEST(star_empty)
{
  ASSERT_MATCH("a*", "");
  PASS();
}

TEST(star_one)
{
  ASSERT_MATCH("a*", "a");
  PASS();
}

TEST(star_two)
{
  ASSERT_MATCH("a*", "aa");
  PASS();
}

TEST(star_greedy)
{
  ASSERT_MATCH_G2_A("(a*)", "aa", 0, 2, 0, 2, 'U');
  PASS();
}

TEST(star_ungreedy)
{
  ASSERT_MATCH_G2_A("(a*?)", "aa", 0, 0, 0, 0, 'U');
  PASS();
}

TEST(star_greedy_then_ungreedy)
{
  ASSERT_MATCH_G2_A("a*(a*?)", "aaaaaa", 0, 6, 6, 6, 'U');
  PASS();
}

TEST(star_ungreedy_then_greedy)
{
  ASSERT_MATCH_G2_A("a*?(a*)", "aaaaaa", 0, 6, 0, 6, 'U');
  PASS();
}

TEST(star_ungreedy_with_assert)
{
  ASSERT_MATCH_G2_A("(a*?)\\b a*", "a a b", 0, 3, 0, 1, A_START);
  PASS();
}

TEST(star_ungreedy_with_assert_unanchored)
{
  ASSERT_MATCH_G2_A("(a*?)\\b a*", "lauaaa a", 3, 8, 3, 6, A_UNANCHORED);
  PASS();
}

SUITE(star)
{
  RUN_TEST(star_empty);
  RUN_TEST(star_one);
  RUN_TEST(star_two);
  RUN_TEST(star_greedy);
  RUN_TEST(star_ungreedy);
  RUN_TEST(star_greedy_then_ungreedy);
  RUN_TEST(star_ungreedy_then_greedy);
  RUN_TEST(star_ungreedy_with_assert);
  RUN_TEST(star_ungreedy_with_assert_unanchored);
}

TEST(quest_empty)
{
  ASSERT_MATCH("a?", "");
  PASS();
}

TEST(quest_one)
{
  ASSERT_MATCH("a?", "a");
  PASS();
}

TEST(quest_two)
{
  ASSERT_NMATCH("a?", "aa");
  PASS();
}

SUITE(quest)
{
  RUN_TEST(quest_empty);
  RUN_TEST(quest_one);
  RUN_TEST(quest_two);
}

TEST(plus_empty)
{
  ASSERT_NMATCH("a+", "");
  PASS();
}

TEST(plus_one)
{
  ASSERT_MATCH("a+", "a");
  PASS();
}

TEST(plus_two)
{
  ASSERT_MATCH("a+", "aa");
  PASS();
}

SUITE(plus)
{
  RUN_TEST(plus_empty);
  RUN_TEST(plus_one);
  RUN_TEST(plus_two);
}

TEST(quant_of_nothing)
{
  ASSERT_NOPARSE("*");
  PASS();
}

TEST(quant_ungreedy_malformed)
{
  ASSERT_NOPARSE("b*\xff");
  PASS();
}

SUITE(quant)
{
  RUN_SUITE(star);
  RUN_SUITE(quest);
  RUN_SUITE(plus);
  RUN_TEST(quant_of_nothing);
  RUN_TEST(quant_ungreedy_malformed);
}

TEST(alt_empty_empty)
{
  ASSERT_MATCH("|", "");
  PASS();
}

TEST(alt_single_empty_first)
{
  ASSERT_MATCH("a|", "a");
  PASS();
}

TEST(alt_single_empty_second)
{
  ASSERT_MATCH("a|", "");
  PASS();
}

TEST(alt_empty_single_first)
{
  ASSERT_MATCH("|a", "");
  PASS();
}

TEST(alt_empty_single_second)
{
  ASSERT_MATCH("|a", "a");
  PASS();
}

TEST(alt_single_single_first)
{
  ASSERT_MATCH("a|b", "a");
  PASS();
}

TEST(alt_single_single_second)
{
  ASSERT_MATCH("a|b", "b");
  PASS();
}

TEST(alt_some_some_first)
{
  ASSERT_MATCH("xyz|[1-9]", "xyz");
  PASS();
}

TEST(alt_some_some_second)
{
  ASSERT_MATCH("xyz|[1-9]", "9");
  PASS();
}

TEST(alt_many)
{
  ASSERT_MATCH("a|b|c|d|e|f|g|h|i|j|k|l", "k");
  PASS();
}

TEST(alt_many_empty_second)
{
  ASSERT_MATCH("a|b|c|||||||", "c");
  PASS();
}

SUITE(alt)
{
  RUN_TEST(alt_empty_empty);
  RUN_TEST(alt_single_empty_first);
  RUN_TEST(alt_single_empty_second);
  RUN_TEST(alt_empty_single_first);
  RUN_TEST(alt_empty_single_second);
  RUN_TEST(alt_single_single_first);
  RUN_TEST(alt_single_single_second);
  RUN_TEST(alt_some_some_first);
  RUN_TEST(alt_some_some_second);
  RUN_TEST(alt_many);
  RUN_TEST(alt_many_empty_second);
}

TEST(anychar_unicode_1)
{
  ASSERT_MATCH(".", "z");
  PASS();
}

TEST(anychar_unicode_2)
{
  ASSERT_MATCH(".", "\xce\x88");
  PASS();
}

TEST(anychar_unicode_3)
{
  ASSERT_MATCH(".", "\xe0\xa4\x82");
  PASS();
}

TEST(anychar_unicode_4)
{
  ASSERT_MATCH(".", "\xf2\x92\x8d\xb2");
  PASS();
}

TEST(anychar_unicode_malformed)
{
  ASSERT_NMATCH(".", "\xff");
  PASS();
}

SUITE(anychar)
{
  RUN_TEST(anychar_unicode_1);
  RUN_TEST(anychar_unicode_2);
  RUN_TEST(anychar_unicode_3);
  RUN_TEST(anychar_unicode_4);
  RUN_TEST(anychar_unicode_malformed);
}

TEST(any_byte_ascii)
{
  ASSERT_MATCH("\\C", "a");
  PASS();
}

TEST(any_byte_nonascii)
{
  ASSERT_MATCH("\\C", "\xff");
  PASS();
}

TEST(any_byte)
{
  char text[2] = {0};
  text[0] = RAND_PARAM(256);
  ASSERT_MATCH_N("\\C", text, 1);
  PASS();
}

SUITE(any_byte)
{
  RUN_TEST(any_byte_ascii);
  RUN_TEST(any_byte_nonascii);
  FUZZ_TEST(any_byte);
}

TEST(cls_escape_any_byte)
{
  ASSERT_NOPARSE("[\\C]");
  PASS();
}

TEST(cls_escape_single)
{
  ASSERT_CC_MATCH("[\\a]", "0x7");
  PASS();
}

TEST(cls_escape_range_start)
{
  ASSERT_CC_MATCH("[\\a-a]", "0x7 a");
  PASS();
}

TEST(cls_escape_range_end)
{
  ASSERT_CC_MATCH("[a-\\n]", "0xA a");
  PASS();
}

TEST(cls_escape_range_both)
{
  ASSERT_CC_MATCH("[\\a-\\r]", "0x7 0xD");
  PASS();
}

TEST(cls_escape_quote)
{
  ASSERT_NOPARSE("[\\Qabc\\E]");
  PASS();
}

TEST(cls_escape_quote_range_end)
{
  ASSERT_NOPARSE("[a-\\Qabc\\E]");
  PASS();
}

SUITE(cls_named); /* provided by test-gen.c */

SUITE(cls_escape)
{
  RUN_TEST(cls_escape_any_byte);
  RUN_TEST(cls_escape_single);
  RUN_TEST(cls_escape_range_start);
  RUN_TEST(cls_escape_range_end);
  RUN_TEST(cls_escape_range_both);
  RUN_TEST(cls_escape_quote);
  RUN_TEST(cls_escape_quote_range_end);
  RUN_SUITE(cls_named);
}

TEST(cls_empty)
{
  ASSERT_NOPARSE("[]");
  PASS();
}

TEST(cls_ending_right_bracket)
{
  ASSERT_CC_MATCH("[]]", "]");
  PASS();
}

TEST(cls_ending_right_bracket_inverted)
{
  ASSERT_CC_MATCH("[^]]", "0x0 0x5C,0x5E 0x10FFFF");
  PASS();
}

TEST(cls_left_bracket_unfinished)
{
  ASSERT_NOPARSE("[[");
  PASS();
}

TEST(cls_left_bracket_malformed)
{
  ASSERT_NOPARSE("[[\xff");
  PASS();
}

TEST(cls_left_bracket_invalid_notcolon)
{
  ASSERT_CC_MATCH("[[p]", "[ [,p p");
  PASS();
}

TEST(cls_single)
{
  ASSERT_CC_MATCH("[a]", "a");
  PASS();
}

TEST(cls_single_malformed)
{
  ASSERT_NOPARSE("[a\xff]");
  PASS();
}

TEST(cls_single_unfinished)
{
  ASSERT_NOPARSE("[a");
  PASS();
}

TEST(cls_range_one)
{
  ASSERT_CC_MATCH("[a-z]", "a z");
  PASS();
}

TEST(cls_range_one_inverted)
{
  ASSERT_CC_MATCH("[^a-z]", "0 `,{ 0x10FFFF");
  PASS();
}

TEST(cls_range_one_unfinished)
{
  ASSERT_NOPARSE("[a-]");
  PASS();
}

TEST(cls_range_one_malformed)
{
  ASSERT_NOPARSE("[a-\xff]");
  PASS();
}

TEST(cls_ending_dash)
{
  ASSERT_CC_MATCH("[-]", "-");
  PASS();
}

TEST(cls_named_unfinished)
{
  ASSERT_NOPARSE("[[:");
  PASS();
}

TEST(cls_named_malformed)
{
  ASSERT_NOPARSE("[[:\xff");
  PASS();
}

TEST(cls_named_unfinished_aftername)
{
  ASSERT_NOPARSE("[[:alnum");
  PASS();
}

TEST(cls_named_unfinished_aftercolon)
{
  ASSERT_NOPARSE("[[:alnum:");
  PASS();
}

TEST(cls_named_invalid_norightbracket)
{
  ASSERT_NOPARSE("[[:alnum:p");
  PASS();
}

TEST(cls_named_unknown)
{
  ASSERT_NOPARSE("[[:unknown:]]");
  PASS();
}

TEST(cls_insensitive)
{
  ASSERT_CC_MATCH("(?i:[a])", "a a,A A");
  PASS();
}

TEST(cls_subclass)
{
  ASSERT_CC_MATCH("[\\w]", "0x30 0x39,0x41 0x5A,0x61 0x7A");
  PASS();
}

TEST(cls_subclass_range_end)
{
  ASSERT_NOPARSE("[a-\\w]");
  PASS();
}

TEST(cls_nevermatch)
{
  ASSERT_NMATCH("[^\\x00-\\x{10FFFF}]", "a");
  PASS();
}

TEST(cls_reversed)
{
  ASSERT_MATCH("[Z-A]", "Z");
  PASS();
}

TEST(cls_reversed_nonmatch)
{
  ASSERT_NMATCH("[Z-A]", ",");
  PASS();
}

TEST(cls_assert)
{
  ASSERT_NOPARSE("[\\A]");
  PASS();
}

TEST(cls_utf8_same_first_byte_and_full_second_byte)
{
  ASSERT_CC_MATCH("[\\x{800}-\\x{83F}]", "0x800 0x83F");
  PASS();
}

TEST(cls_utf8_same_first_byte_and_almost_full_second_byte)
{
  ASSERT_CC_MATCH("[\\x{800}-\\x{83E}]", "0x800 0x83E");
  PASS();
}

TEST(cls_utf8_same_first_byte_and_almost_full_second_byte_1)
{
  ASSERT_CC_MATCH("[\\x{801}-\\x{83F}]", "0x801 0x83F");
  PASS();
}

TEST(cls_utf8_adjacent_first_bytes_and_almost_full_second_byte)
{
  ASSERT_CC_MATCH("[\\x{800}-\\x{87E}]", "0x800 0x87E");
  PASS();
}

TEST(cls_utf8_adjacent_first_bytes_and_nonfull_second_byte)
{
  ASSERT_CC_MATCH("[\\x{801}-\\x{87E}]", "0x800 0x87E");
  PASS();
}

TEST(cls_utf8_two_subsequent_ranges_with_same_first_bytes)
{
  ASSERT_CC_MATCH(
      "[\\x{800}-\\x{870}\\x{872}-\\x{8BF}]", "0x800 0x870,0x872 0x8BF");
  PASS();
}

TEST(cls_utf8_two_nonadjacent_ranges_with_adjacent_second_bytes)
{
  ASSERT_CC_MATCH(
      "[\\x{800}-\\x{83E}\\x{840}-\\x{87E}]", "0x800 0x83E,0x840 0x87E");
  PASS();
}

TEST(cls_utf8_two_nonadjacent_ranges_with_adjacent_single_second_bytes)
{
  ASSERT_CC_MATCH(
      "[\\x{80}-\\x{9E}\\x{100}-\\x{11E}]", "0x80 0x9E,0x100 0x11E");
  PASS();
}

TEST(cls_utf8_range_with_common_suffixes)
{
  ASSERT_CC_MATCH(
      "[\\x{800}-\\x{83E}\\x{900}-\\x{93E}]", "0x800 0x83E,0x900 0x93E");
  PASS();
}

TEST(cls_utf8_range_with_common_suffixes_1)
{
  ASSERT_CC_MATCH(
      "[\\x{800}\\x{803}-\\x{83F}\\x{901}\\x{903}-\\x{93F}]",
      "0x800 0x800,0x803 0x83F,0x901 0x901,0x903 0x93F");
  PASS();
}

TEST(cls_utf8_ranges_with_intersections)
{
  ASSERT_CC_MATCH("[\\x{800}-\\x{801}\\x{801}-\\x{802}]", "0x800 0x802");
  PASS();
}

TEST(cls_utf8_ranges_redundant)
{
  ASSERT_CC_MATCH("[\\x{800}-\\x{840}\\x{820}-\\x{830}]", "0x800 0x840");
  PASS();
}

TEST(cls_utf8_insensitive_whole_plane)
{
  ASSERT_CC_MATCH("(?is).", "0x0 0x10FFFF");
  PASS();
}

TEST(cls_utf8_insensitive_ascii)
{
  ASSERT_CC_MATCH("(?i)[abcd]", "a a,b b,c c,d d,A A,B B,C C,D D");
  PASS();
}

TEST(cls_utf8_insensitive_ascii_many_non_adjacent)
{
  ASSERT_CC_MATCH(
      "(?i)[acegiknpr]", "A A,C C,E E,G G,I I,K K,N N,P P,R R,a a,c c,e e,g "
                         "g,i i,k k,n n,p p,r r");
  PASS();
}

TEST(cls_utf8_insensitive_ascii_many_non_adjacent_1)
{
  ASSERT_CC_MATCH(
      "(?i)[!A%CEG_]",
      "0x21 0x21,A A,0x25 0x25,C C,E E,G G,_ _,a a,c c,e e,g g");
  PASS();
}

TEST(cls_utf8_insensitive_inverted)
{
  ASSERT_CC_MATCH("(?i)[^BDF]", "0 A,C C,E E,G a,c c,e e,g 0x10FFFF");
  PASS();
}

SUITE(cls_utf8)
{
  RUN_TEST(cls_utf8_same_first_byte_and_full_second_byte);
  RUN_TEST(cls_utf8_same_first_byte_and_almost_full_second_byte);
  RUN_TEST(cls_utf8_same_first_byte_and_almost_full_second_byte_1);
  RUN_TEST(cls_utf8_adjacent_first_bytes_and_almost_full_second_byte);
  RUN_TEST(cls_utf8_adjacent_first_bytes_and_nonfull_second_byte);
  RUN_TEST(cls_utf8_two_subsequent_ranges_with_same_first_bytes);
  RUN_TEST(cls_utf8_two_nonadjacent_ranges_with_adjacent_second_bytes);
  RUN_TEST(cls_utf8_two_nonadjacent_ranges_with_adjacent_single_second_bytes);
  RUN_TEST(cls_utf8_range_with_common_suffixes);
  RUN_TEST(cls_utf8_range_with_common_suffixes_1);
  RUN_TEST(cls_utf8_ranges_with_intersections);
  RUN_TEST(cls_utf8_ranges_redundant);
  RUN_TEST(cls_utf8_insensitive_whole_plane);
  RUN_TEST(cls_utf8_insensitive_ascii);
  RUN_TEST(cls_utf8_insensitive_ascii_many_non_adjacent);
  RUN_TEST(cls_utf8_insensitive_ascii_many_non_adjacent_1);
  RUN_TEST(cls_utf8_insensitive_inverted);
}

SUITE(cls)
{
  RUN_SUITE(cls_escape);
  RUN_TEST(cls_empty);
  RUN_TEST(cls_ending_right_bracket);
  RUN_TEST(cls_ending_right_bracket_inverted);
  RUN_TEST(cls_left_bracket_unfinished);
  RUN_TEST(cls_left_bracket_malformed);
  RUN_TEST(cls_left_bracket_invalid_notcolon);
  RUN_TEST(cls_single);
  RUN_TEST(cls_single_malformed);
  RUN_TEST(cls_single_unfinished);
  RUN_TEST(cls_range_one);
  RUN_TEST(cls_range_one_inverted);
  RUN_TEST(cls_range_one_unfinished);
  RUN_TEST(cls_range_one_malformed);
  RUN_TEST(cls_ending_dash);
  RUN_TEST(cls_named_unfinished);
  RUN_TEST(cls_named_malformed);
  RUN_TEST(cls_named_unfinished_aftername);
  RUN_TEST(cls_named_unfinished_aftercolon);
  RUN_TEST(cls_named_invalid_norightbracket);
  RUN_TEST(cls_named_unknown);
  RUN_TEST(cls_insensitive);
  RUN_TEST(cls_subclass);
  RUN_TEST(cls_subclass_range_end);
  RUN_TEST(cls_nevermatch);
  RUN_TEST(cls_reversed);
  RUN_TEST(cls_reversed_nonmatch);
  RUN_TEST(cls_assert);
  RUN_SUITE(cls_utf8);
}

TEST(escape_null)
{
  ASSERT_MATCH_N("\\0", "\x00", 1);
  PASS();
}

TEST(escape_bell)
{
  ASSERT_MATCH_G1("\\a", "\x07", 0, 1);
  PASS();
}

TEST(escape_formfeed)
{
  ASSERT_MATCH_G1("\\f", "\x0C", 0, 1);
  PASS();
}

TEST(escape_tab)
{
  ASSERT_MATCH_G1("\\t", "\x09", 0, 1);
  PASS();
}

TEST(escape_newline)
{
  ASSERT_MATCH_G1("\\n", "\x0A", 0, 1);
  PASS();
}

TEST(escape_return)
{
  ASSERT_MATCH_G1("\\r", "\x0D", 0, 1);
  PASS();
}

TEST(escape_vtab)
{
  ASSERT_MATCH_G1("\\v", "\v", 0, 1);
  PASS();
}

TEST(escape_question)
{
  ASSERT_MATCH_G1("\\?", "?", 0, 1);
  PASS();
}

TEST(escape_asterisk)
{
  ASSERT_MATCH_G1("\\*", "*", 0, 1);
  PASS();
}

TEST(escape_plus)
{
  ASSERT_MATCH_G1("\\+", "+", 0, 1);
  PASS();
}

TEST(escape_open_parenthesis)
{
  ASSERT_MATCH_G1("\\(", "(", 0, 1);
  PASS();
}

TEST(escape_close_parenthesis)
{
  ASSERT_MATCH_G1("\\)", ")", 0, 1);
  PASS();
}

TEST(escape_open_bracket)
{
  ASSERT_MATCH_G1("\\[", "[", 0, 1);
  PASS();
}

TEST(escape_close_bracket)
{
  ASSERT_MATCH_G1("\\]", "]", 0, 1);
  PASS();
}

TEST(escape_open_curly_bracket)
{
  ASSERT_MATCH_G1("\\{", "{", 0, 1);
  PASS();
}

TEST(escape_close_curly_bracket)
{
  ASSERT_MATCH_G1("\\}", "}", 0, 1);
  PASS();
}

TEST(escape_pipe)
{
  ASSERT_MATCH_G1("\\|", "|", 0, 1);
  PASS();
}

TEST(escape_caret)
{
  ASSERT_MATCH("\\^", "^");
  PASS();
}

TEST(escape_dollar)
{
  ASSERT_MATCH("\\$", "$");
  PASS();
}

TEST(escape_dash)
{
  ASSERT_MATCH("\\-", "-");
  PASS();
}

TEST(escape_slash)
{
  ASSERT_MATCH_G1("\\\\", "\\", 0, 1);
  PASS();
}

TEST(escape_octal_1)
{
  ASSERT_MATCH_G1("\\1", "\001", 0, 1);
  PASS();
}

TEST(escape_octal_2)
{
  ASSERT_MATCH_G1("\\73", "\073", 0, 1);
  PASS();
}

TEST(escape_octal_3)
{
  ASSERT_MATCH_G1("\\123", "\123", 0, 1);
  PASS();
}

TEST(escape_octal_nonascii)
{
  ASSERT_MATCH_G1("\\777", "\xc7\xbf", 0, 2);
  PASS();
}

TEST(escape_octal_malformed)
{
  ASSERT_NOPARSE("\\1\xff");
  PASS();
}

TEST(escape_octal_truncated_1)
{
  /* octal escapes less than three characters should be truncated by a non-octal
   * character */
  ASSERT_MATCH_G1("\\7a", "\007a", 0, 2);
  PASS();
}

TEST(escape_octal_truncated_2)
{
  /* octal escapes less than three characters should be truncated by a non-octal
   * character */
  ASSERT_MATCH_G1("\\30a", "\030a", 0, 2);
  PASS();
}

SUITE(escape_octal)
{
  RUN_TEST(escape_octal_1);
  RUN_TEST(escape_octal_2);
  RUN_TEST(escape_octal_3);
  RUN_TEST(escape_octal_nonascii);
  RUN_TEST(escape_octal_malformed);
  RUN_TEST(escape_octal_truncated_1);
  RUN_TEST(escape_octal_truncated_2);
}

TEST(escape_hex)
{
  ASSERT_MATCH_G1("\\x20", "\x20", 0, 1);
  PASS();
}

TEST(escape_hex_unfinished)
{
  ASSERT_NOPARSE("\\x");
  PASS();
}

TEST(escape_hex_unfinished_1)
{
  ASSERT_NOPARSE("\\x1");
  PASS();
}

TEST(escape_hex_malformed)
{
  ASSERT_NOPARSE("\\x\xff");
  PASS();
}

TEST(escape_hex_malformed_1)
{
  ASSERT_NOPARSE("\\x1\xff");
  PASS();
}

TEST(escape_hex_invalid)
{
  ASSERT_NOPARSE("\\xx");
  PASS();
}

TEST(escape_hex_invalid_1)
{
  ASSERT_NOPARSE("\\x1x");
  PASS();
}

TEST(escape_hex_invalid_2)
{
  ASSERT_NOPARSE("\\x/");
  PASS();
}

TEST(escape_hex_lowercase)
{
  ASSERT_MATCH("\\x5b", "[");
  PASS();
}

SUITE(escape_hex)
{
  RUN_TEST(escape_hex);
  RUN_TEST(escape_hex_unfinished);
  RUN_TEST(escape_hex_unfinished_1);
  RUN_TEST(escape_hex_malformed);
  RUN_TEST(escape_hex_malformed_1);
  RUN_TEST(escape_hex_invalid);
  RUN_TEST(escape_hex_invalid_1);
  RUN_TEST(escape_hex_lowercase);
  RUN_TEST(escape_hex_invalid_2);
}

TEST(escape_hex_long_1)
{
  ASSERT_MATCH("\\x{1}", "\x01");
  PASS();
}

TEST(escape_hex_long_2)
{
  ASSERT_MATCH("\\x{20}", " ");
  PASS();
}

TEST(escape_hex_long_3)
{
  ASSERT_MATCH("\\x{7FF}", "\xdf\xbf");
  PASS();
}

TEST(escape_hex_long_4)
{
  ASSERT_MATCH("\\x{4096}", "\xe4\x82\x96");
  PASS();
}

TEST(escape_hex_long_5)
{
  ASSERT_MATCH("\\x{15392}", "\xf0\x95\x8e\x92");
  PASS();
}

TEST(escape_hex_long_6)
{
  ASSERT_MATCH("\\x{10FF01}", "\xf4\x8f\xbc\x81");
  PASS();
}

TEST(escape_hex_long_unfinished)
{
  ASSERT_NOPARSE("\\x{");
  PASS();
}

TEST(escape_hex_long_unfinished_aftersome)
{
  ASSERT_NOPARSE("\\x{1");
  PASS();
}

TEST(escape_hex_long_too_long)
{
  /* bracketed hex literals should only be up to six characters */
  ASSERT_NOPARSE("\\x{1000000}");
  PASS();
}

TEST(escape_hex_long_out_of_range)
{
  /* bracketed hex literals should not be greater than 0x10FFFF */
  ASSERT_NOPARSE("\\x{110000}");
  PASS();
}

TEST(escape_hex_long_invalid)
{
  ASSERT_NOPARSE("\\x{&&}");
  PASS();
}

TEST(escape_hex_long_empty)
{
  ASSERT_NOPARSE("\\x{}");
  PASS();
}

SUITE(escape_hex_long)
{
  RUN_TEST(escape_hex_long_1);
  RUN_TEST(escape_hex_long_2);
  RUN_TEST(escape_hex_long_3);
  RUN_TEST(escape_hex_long_4);
  RUN_TEST(escape_hex_long_5);
  RUN_TEST(escape_hex_long_6);
  RUN_TEST(escape_hex_long_unfinished);
  RUN_TEST(escape_hex_long_unfinished_aftersome);
  RUN_TEST(escape_hex_long_too_long);
  RUN_TEST(escape_hex_long_out_of_range);
  RUN_TEST(escape_hex_long_invalid);
  RUN_TEST(escape_hex_long_empty);
}

TEST(escape_any_byte)
{
  ASSERT_MATCH("\\C", "\x11");
  PASS();
}

TEST(escape_quote_empty)
{
  ASSERT_MATCH("\\Q\\E", "");
  PASS();
}

TEST(escape_quote_text)
{
  ASSERT_MATCH("\\Qabc\\E", "abc");
  PASS();
}

TEST(escape_quote_unfinished)
{
  ASSERT_MATCH("\\Qabc", "abc");
  PASS();
}

TEST(escape_quote_unfinished_empty)
{
  ASSERT_MATCH("abc\\Q", "abc");
  PASS();
}

TEST(escape_quote_single_slash_unfinished)
{
  /* a *single* slash at the end of a string within a quoted escape is just a
   * slash */
  ASSERT_MATCH("\\Q\\", "\\");
  PASS();
}

TEST(escape_quote_double_slash)
{
  /* a double slash is escaped as a single slash */
  ASSERT_MATCH("\\Q\\\\\\E", "\\");
  PASS();
}

TEST(escape_quote_single_slash_with_non_E)
{
  /* a slash followed by some non-E character is a single slash followed by that
   * character */
  ASSERT_MATCH("\\Q\\A\\E", "\\A");
  PASS();
}

TEST(escape_quote_malformed)
{
  ASSERT_NOPARSE("\\Q\xff");
  PASS();
}

TEST(escape_quote_malformed_afterslash)
{
  ASSERT_NOPARSE("\\Q\\\xff");
  PASS();
}

TEST(escape_quote_many)
{
  ASSERT_MATCH(
      "\\QThe industrial revolution and its consequences",
      "The industrial revolution and its consequences");
  PASS();
}

SUITE(escape_quote)
{
  RUN_TEST(escape_quote_empty);
  RUN_TEST(escape_quote_text);
  RUN_TEST(escape_quote_unfinished);
  RUN_TEST(escape_quote_unfinished_empty);
  RUN_TEST(escape_quote_single_slash_unfinished);
  RUN_TEST(escape_quote_double_slash);
  RUN_TEST(escape_quote_single_slash_with_non_E);
  RUN_TEST(escape_quote_malformed);
  RUN_TEST(escape_quote_malformed_afterslash);
  RUN_TEST(escape_quote_many);
}

SUITE(escape_perlclass); /* provided by test-gen.c */

TEST(escape_unfinished)
{
  ASSERT_NOPARSE("\\");
  PASS();
}

TEST(escape_invalid)
{
  ASSERT_NOPARSE("\\/");
  PASS();
}

SUITE(escape)
{
  RUN_TEST(escape_null);
  RUN_TEST(escape_bell);
  RUN_TEST(escape_formfeed);
  RUN_TEST(escape_tab);
  RUN_TEST(escape_newline);
  RUN_TEST(escape_return);
  RUN_TEST(escape_vtab);
  RUN_TEST(escape_question);
  RUN_TEST(escape_asterisk);
  RUN_TEST(escape_plus);
  RUN_TEST(escape_open_parenthesis);
  RUN_TEST(escape_close_parenthesis);
  RUN_TEST(escape_open_bracket);
  RUN_TEST(escape_close_bracket);
  RUN_TEST(escape_open_curly_bracket);
  RUN_TEST(escape_close_curly_bracket);
  RUN_TEST(escape_slash);
  RUN_TEST(escape_pipe);
  RUN_TEST(escape_caret);
  RUN_TEST(escape_dollar);
  RUN_TEST(escape_dash);
  RUN_SUITE(escape_octal);
  RUN_SUITE(escape_hex);
  RUN_SUITE(escape_hex_long);
  RUN_TEST(escape_any_byte);
  RUN_SUITE(escape_quote);
  RUN_SUITE(escape_perlclass);
  RUN_TEST(escape_unfinished);
  RUN_TEST(escape_invalid);
}

TEST(repetition_zero_empty)
{
  ASSERT_MATCH("a{0}", "");
  PASS();
}

TEST(repetition_zero_one)
{
  ASSERT_NMATCH("a{0}", "a");
  PASS();
}

TEST(repetition_zero_two)
{
  ASSERT_NMATCH("a{0}", "aa");
  PASS();
}

TEST(repetition_zero_nonmatch)
{
  ASSERT_NMATCH("a{0}", "b");
  PASS();
}

TEST(repetition_one_empty)
{
  ASSERT_NMATCH("a{1}", "");
  PASS();
}

TEST(repetition_one_one)
{
  ASSERT_MATCH("a{1}", "a");
  PASS();
}

TEST(repetition_one_two)
{
  ASSERT_NMATCH("a{1}", "aa");
  PASS();
}

TEST(repetition_one_nonmatch)
{
  ASSERT_NMATCH("a{1}", "b");
  PASS();
}

TEST(repetition_two_empty)
{
  ASSERT_NMATCH("a{2}", "");
  PASS();
}

TEST(repetition_two_one)
{
  ASSERT_NMATCH("a{2}", "a");
  PASS();
}

TEST(repetition_two_two)
{
  ASSERT_MATCH("a{2}", "aa");
  PASS();
}

TEST(repetition_two_three)
{
  ASSERT_NMATCH("a{2}", "aaa");
  PASS();
}

TEST(repetition_two_nonmatch)
{
  ASSERT_NMATCH("a{2}", "b");
  PASS();
}

TEST(repetition_zero_infty_empty)
{
  ASSERT_MATCH("a{0,}", "");
  PASS();
}

TEST(repetition_zero_infty_one)
{
  ASSERT_MATCH("a{0,}", "a");
  PASS();
}

TEST(repetition_zero_infty_two)
{
  ASSERT_MATCH("a{0,}", "aa");
  PASS();
}

TEST(repetition_zero_infty_nonmatch)
{
  ASSERT_NMATCH("a{0,}", "b");
  PASS();
}

TEST(repetition_one_infty_empty)
{
  ASSERT_NMATCH("a{1,}", "");
  PASS();
}

TEST(repetition_one_infty_one)
{
  ASSERT_MATCH("a{1,}", "a");
  PASS();
}

TEST(repetition_one_infty_two)
{
  ASSERT_MATCH("a{1,}", "aa");
  PASS();
}

TEST(repetition_one_infty_nonmatch)
{
  ASSERT_NMATCH("a{1,}", "b");
  PASS();
}

TEST(repetition_two_infty_empty)
{
  ASSERT_NMATCH("a{2,}", "");
  PASS();
}

TEST(repetition_two_infty_one)
{
  ASSERT_NMATCH("a{2,}", "a");
  PASS();
}

TEST(repetition_two_infty_two)
{
  ASSERT_MATCH("a{2,}", "aa");
  PASS();
}

TEST(repetition_two_infty_three)
{
  ASSERT_MATCH("a{2,}", "aaa");
  PASS();
}

TEST(repetition_two_infty_nonmatch)
{
  ASSERT_NMATCH("a{2,}", "b");
  PASS();
}

TEST(repetition_one_three_empty)
{
  ASSERT_NMATCH("a{1,3}", "");
  PASS();
}

TEST(repetition_one_three_one)
{
  ASSERT_MATCH("a{1,3}", "a");
  PASS();
}

TEST(repetition_one_three_two)
{
  ASSERT_MATCH("a{1,3}", "aa");
  PASS();
}

TEST(repetition_one_three_three)
{
  ASSERT_MATCH("a{1,3}", "aaa");
  PASS();
}

TEST(repetition_one_three_four)
{
  ASSERT_NMATCH("a{1,3}", "aaaa");
  PASS();
}

TEST(repetition_one_three_nonmatch)
{
  ASSERT_NMATCH("a{1,3}", "b");
  PASS();
}

TEST(repetition_zero_zero_match)
{
  ASSERT_MATCH("a{0,0}", "");
  PASS();
}

TEST(repetition_zero_zero_nonmatch)
{
  ASSERT_NMATCH("a{0,0}", "aa");
  PASS();
}

TEST(repetition_malformed)
{
  ASSERT_NOPARSE("a{\xff}");
  PASS();
}

TEST(repetition_malformed_afterdigit)
{
  ASSERT_NOPARSE("a{1\xff}");
  PASS();
}

TEST(repetition_unfinished)
{
  ASSERT_NOPARSE("a{");
  PASS();
}

TEST(repetition_unfinished_afterdigit)
{
  ASSERT_NOPARSE("a{1");
  PASS();
}

TEST(repetition_nomin)
{
  ASSERT_NOPARSE("a{,");
  PASS();
}

TEST(repetition_toomanydigits)
{
  ASSERT_NOPARSE("a{123412341234123412341234}");
  PASS();
}

TEST(repetition_empty)
{
  ASSERT_NOPARSE("a{}");
  PASS();
}

TEST(repetition_upper_unfinished)
{
  ASSERT_NOPARSE("w{5,");
  PASS();
}

TEST(repetition_upper_malformed)
{
  ASSERT_NOPARSE("l{5,\xff}");
  PASS();
}

TEST(repetition_upper_unfinished_afternumber)
{
  ASSERT_NOPARSE("j{100,5");
  PASS();
}

TEST(repetition_upper_malformed_afternumber)
{
  ASSERT_NOPARSE("q{100,5\xff}");
  PASS();
}

TEST(repetition_upper_invalid_afternumber)
{
  ASSERT_NOPARSE("w{97,677a}");
  PASS();
}

TEST(repetition_upper_invalid)
{
  ASSERT_NOPARSE("9{5,5223222111}");
  PASS();
}

TEST(repetition_upper_badsep)
{
  ASSERT_NOPARSE("p{5a11}");
  PASS();
}

TEST(repetition_empty_regex)
{
  ASSERT_NOPARSE("{2,3}");
  PASS();
}

TEST(repetition_many)
{
  ASSERT_MATCH("a{2,3}b{10,20}c{1,2}d{3,5}", "aabbbbbbbbbbbbbbbccdddd");
  PASS();
}

SUITE(repetition)
{
  RUN_TEST(repetition_zero_empty);
  RUN_TEST(repetition_zero_one);
  RUN_TEST(repetition_zero_two);
  RUN_TEST(repetition_zero_nonmatch);
  RUN_TEST(repetition_one_empty);
  RUN_TEST(repetition_one_one);
  RUN_TEST(repetition_one_two);
  RUN_TEST(repetition_one_nonmatch);
  RUN_TEST(repetition_two_empty);
  RUN_TEST(repetition_two_one);
  RUN_TEST(repetition_two_two);
  RUN_TEST(repetition_two_three);
  RUN_TEST(repetition_two_nonmatch);
  RUN_TEST(repetition_zero_infty_empty);
  RUN_TEST(repetition_zero_infty_one);
  RUN_TEST(repetition_zero_infty_two);
  RUN_TEST(repetition_zero_infty_nonmatch);
  RUN_TEST(repetition_one_infty_empty);
  RUN_TEST(repetition_one_infty_one);
  RUN_TEST(repetition_one_infty_two);
  RUN_TEST(repetition_one_infty_nonmatch);
  RUN_TEST(repetition_two_infty_empty);
  RUN_TEST(repetition_two_infty_one);
  RUN_TEST(repetition_two_infty_two);
  RUN_TEST(repetition_two_infty_three);
  RUN_TEST(repetition_two_infty_nonmatch);
  RUN_TEST(repetition_one_three_empty);
  RUN_TEST(repetition_one_three_one);
  RUN_TEST(repetition_one_three_two);
  RUN_TEST(repetition_one_three_three);
  RUN_TEST(repetition_one_three_four);
  RUN_TEST(repetition_one_three_nonmatch);
  RUN_TEST(repetition_zero_zero_match);
  RUN_TEST(repetition_zero_zero_nonmatch);
  RUN_TEST(repetition_malformed);
  RUN_TEST(repetition_malformed_afterdigit);
  RUN_TEST(repetition_unfinished);
  RUN_TEST(repetition_unfinished_afterdigit);
  RUN_TEST(repetition_toomanydigits);
  RUN_TEST(repetition_empty);
  RUN_TEST(repetition_upper_unfinished);
  RUN_TEST(repetition_upper_malformed);
  RUN_TEST(repetition_upper_invalid);
  RUN_TEST(repetition_upper_badsep);
  RUN_TEST(repetition_upper_unfinished_afternumber);
  RUN_TEST(repetition_upper_malformed_afternumber);
  RUN_TEST(repetition_upper_invalid_afternumber);
  RUN_TEST(repetition_empty_regex);
  RUN_TEST(repetition_many);
}

TEST(grp_flag_i_match)
{
  ASSERT_MATCH("(?i:a)", "A");
  PASS();
}

TEST(grp_flag_i_nmatch)
{
  ASSERT_NMATCH("(?i:a)", "B");
  PASS();
}

TEST(grp_flag_i_off_match)
{
  ASSERT_MATCH("(?i:(?-i:a))", "a");
  PASS();
}

TEST(grp_flag_i_off_nmatch)
{
  ASSERT_NMATCH("(?i:(?-i:a))", "A");
  PASS();
}

SUITE(grp_flag_i)
{
  RUN_TEST(grp_flag_i_match);
  RUN_TEST(grp_flag_i_nmatch);
  RUN_TEST(grp_flag_i_off_match);
  RUN_TEST(grp_flag_i_off_nmatch);
}

TEST(grp_flag_s_match)
{
  ASSERT_MATCH("(?s:.)", "\n");
  PASS();
}

TEST(grp_flag_s_nmatch)
{
  /* since with s-flag . matches everything, just give it an invalid utf-8 */
  ASSERT_NMATCH("(?s:.)", "\xff");
  PASS();
}

TEST(grp_flag_s_off_match)
{
  ASSERT_MATCH("(?s:(?-s:.))", "a");
  PASS();
}

TEST(grp_flag_s_off_nmatch)
{
  ASSERT_NMATCH("(?s:(?-s:.))", "\n");
  PASS();
}

SUITE(grp_flag_s)
{
  RUN_TEST(grp_flag_s_match);
  RUN_TEST(grp_flag_s_nmatch);
  RUN_TEST(grp_flag_s_off_match);
  RUN_TEST(grp_flag_s_off_nmatch);
}

TEST(grp_flag_m_match)
{
  ASSERT_MATCH("(?m:$\n)", "\n");
  PASS();
}

TEST(grp_flag_m_nmatch)
{
  ASSERT_NMATCH("(?m:$a)", "");
  PASS();
}

TEST(grp_flag_m_off_match)
{
  ASSERT_MATCH("(?m:(?-m:\n$))", "\n");
  PASS();
}

TEST(grp_flag_m_off_nmatch)
{
  ASSERT_NMATCH("(?m:(?-m:$\n))", "\n");
  PASS();
}

SUITE(grp_flag_m)
{
  RUN_TEST(grp_flag_m_match);
  RUN_TEST(grp_flag_m_nmatch);
  RUN_TEST(grp_flag_m_off_match);
  RUN_TEST(grp_flag_m_off_nmatch);
}

TEST(grp_flag_u_match)
{
  ASSERT_MATCH_G1_A("(?u)a*", "aa", 0, 0, 'U');
  PASS();
}

TEST(grp_flag_u_nmatch)
{
  ASSERT_NMATCH("(?u)a+", "b");
  PASS();
}

TEST(grp_flag_u_off_match)
{
  ASSERT_MATCH_G1_A("(?u:(?-u:a*))", "aa", 0, 2, 'B');
  PASS();
}

TEST(grp_flag_u_off_nmatch)
{
  ASSERT_NMATCH("(?u:(?-u:a*))", "b");
  PASS();
}

SUITE(grp_flag_u)
{
  RUN_TEST(grp_flag_u_match);
  RUN_TEST(grp_flag_u_nmatch);
  RUN_TEST(grp_flag_u_off_match);
  RUN_TEST(grp_flag_u_off_nmatch);
}

TEST(grp_named_regular)
{
  ASSERT_MATCH("(?<name>a)", "a");
  PASS();
}

TEST(grp_named_regular_unfinished)
{
  ASSERT_NOPARSE("(?<name");
  PASS();
}

TEST(grp_named_regular_malformed_before_name)
{
  ASSERT_NOPARSE("(?\xff");
  PASS();
}

TEST(grp_named_regular_malformed)
{
  ASSERT_NOPARSE("(?<name\xff");
  PASS();
}

TEST(grp_named_perl)
{
  ASSERT_MATCH("(?P<name>a)", "a");
  PASS();
}

TEST(grp_named_perl_unfinished_before_name)
{
  ASSERT_NOPARSE("(?P");
  PASS();
}

TEST(grp_named_perl_malformed_before_name)
{
  ASSERT_NOPARSE("(?P\xff");
  PASS();
}

TEST(grp_named_perl_unfinished)
{
  ASSERT_NOPARSE("(?P<name");
  PASS();
}

TEST(grp_named_perl_malformed)
{
  ASSERT_NOPARSE("(?P<name\xff");
  PASS();
}

TEST(grp_named_perl_invalid)
{
  ASSERT_MATCH("(?P<name>a)", "a");
  PASS();
}

TEST(grp_named_perl_invalid_before_name)
{
  ASSERT_NOPARSE("(?Pl");
  PASS();
}

SUITE(grp_named)
{
  RUN_TEST(grp_named_regular);
  RUN_TEST(grp_named_regular_unfinished);
  RUN_TEST(grp_named_regular_malformed);
  RUN_TEST(grp_named_regular_malformed_before_name);
  RUN_TEST(grp_named_perl_unfinished_before_name);
  RUN_TEST(grp_named_perl_malformed_before_name);
  RUN_TEST(grp_named_perl);
  RUN_TEST(grp_named_perl_unfinished);
  RUN_TEST(grp_named_perl_invalid_before_name);
}

TEST(grp_unfinished)
{
  ASSERT_NOPARSE("(");
  PASS();
}

TEST(grp_unfinished_afterspecial)
{
  ASSERT_NOPARSE("(?");
  PASS();
}

TEST(grp_unfinished_afterflag)
{
  ASSERT_NOPARSE("(?i");
  PASS();
}

TEST(grp_malformed)
{
  ASSERT_NOPARSE("(\xff");
  PASS();
}

TEST(grp_empty)
{
  ASSERT_MATCH_G2("()", "", 0, 0, 0, 0);
  PASS();
}

TEST(grp_nonmatching_unfinished)
{
  ASSERT_NOPARSE("(?");
  PASS();
}

TEST(grp_nonmatching_malformed)
{
  ASSERT_NOPARSE("(?\xff");
  PASS();
}

TEST(grp_nonmatching_in_zero_quant)
{
  ASSERT_MATCH("(?:){0,0}", "");
  PASS();
}

TEST(grp_negate_twice)
{
  ASSERT_NOPARSE("(?--:)");
  PASS();
}

TEST(grp_inline_flag_set_match)
{
  ASSERT_MATCH("(a(?i)a)", "aA");
  PASS();
}

TEST(grp_inline_flag_reset_match)
{
  ASSERT_MATCH("(a(?i)a(?-i)a)", "aAa");
  PASS();
}

TEST(grp_inline_flag_reset_nmatch)
{
  ASSERT_NMATCH("a(?i)a(?-i)a", "aAA");
  PASS();
}

TEST(grp_after_cat)
{
  ASSERT_MATCH_G2("a(b)", "ab", 0, 2, 1, 2);
  PASS();
}

TEST(grp_inline_flag_no_spans)
{
  /* inline flags shouldn't cause groups to be set */
  ASSERT_MATCH_G2("(?u)abc", "abc", 0, 3, 0, 0);
  PASS();
}

SUITE(grp_inline_flag)
{
  RUN_TEST(grp_inline_flag_set_match);
  RUN_TEST(grp_inline_flag_reset_match);
  RUN_TEST(grp_inline_flag_reset_nmatch);
  RUN_TEST(grp_inline_flag_no_spans);
}

TEST(grp_flag_set_then_reset)
{
  ASSERT_NMATCH("(?i-i:a)", "A");
  PASS();
}

TEST(grp_flag_invalid)
{
  ASSERT_NOPARSE("(?x)");
  PASS();
}

TEST(grp_concat)
{
  ASSERT_MATCH("(abcdefghijklmnop)", "abcdefghijklmnop");
  PASS();
}

TEST(grp_concat_alts)
{
  ASSERT_MATCH("(abc|def|ghi|jkl)", "jkl");
  PASS();
}

TEST(grp_nested_inlines)
{
  ASSERT_MATCH("((?i)abc(?u)def(?m)ghi(?s)jkl)", "abcdefghijkl");
  PASS();
}

TEST(grp_invalid_unmatched_rparen)
{
  ASSERT_NOPARSE(")");
  PASS();
}

TEST(grp_invalid_unmatched_lparen)
{
  ASSERT_NOPARSE("(abc");
  PASS();
}

SUITE(grp)
{
  RUN_SUITE(grp_flag_i);
  RUN_SUITE(grp_flag_s);
  RUN_SUITE(grp_flag_m);
  RUN_SUITE(grp_flag_u);
  RUN_TEST(grp_flag_invalid);
  RUN_SUITE(grp_named);
  RUN_TEST(grp_unfinished);
  RUN_TEST(grp_unfinished_afterspecial);
  RUN_TEST(grp_unfinished_afterflag);
  RUN_TEST(grp_empty);
  RUN_TEST(grp_nonmatching_unfinished);
  RUN_TEST(grp_nonmatching_malformed);
  RUN_TEST(grp_nonmatching_in_zero_quant);
  RUN_TEST(grp_negate_twice);
  RUN_SUITE(grp_inline_flag);
  RUN_TEST(grp_after_cat);
  RUN_TEST(grp_flag_set_then_reset);
  RUN_TEST(grp_malformed);
  RUN_TEST(grp_concat);
  RUN_TEST(grp_concat_alts);
  RUN_TEST(grp_nested_inlines);
  RUN_TEST(grp_invalid_unmatched_rparen);
  RUN_TEST(grp_invalid_unmatched_lparen);
}

TEST(set_two_char)
{
  ASSERT_MATCH_S2("a", "a", "a");
  PASS();
}

TEST(set_two_char_bounds)
{
  ASSERT_MATCH_S2_G1("a", "a", "a", 0, 1, 0, 1);
  PASS();
}

TEST(set_two_char_grp)
{
  ASSERT_MATCH_S2_G2("(a)", "(a)", "a", 0, 1, 0, 1, 0, 1, 0, 1);
  PASS();
}

TEST(set_many)
{
  re *r;
  int err = re_init_full(&r, NULL, 0, NULL);
  u32 i;
  if (err == ERR_MEM)
    goto oom;
  ASSERT_EQ(err, 0);
  for (i = 0; i < 26; i++) {
    char reg[] = "a";
    reg[0] += i;
    err = re_union(r, reg, 1);
    if (err == ERR_MEM)
      goto oom;
    ASSERT_EQ(err, 0);
  }
  re_destroy(r);
  PASS();
oom:
  re_destroy(r);
  OOM();
}

SUITE(set)
{
  RUN_TEST(set_two_char);
  RUN_TEST(set_two_char_bounds);
  RUN_TEST(set_two_char_grp);
  RUN_TEST(set_many);
}

TEST(assert_line_begin_empty)
{
  ASSERT_MATCH("^", "");
  PASS();
}

TEST(assert_line_begin_beforesome)
{
  ASSERT_MATCH("^abc", "abc");
  PASS();
}

TEST(assert_line_begin_aftersome)
{
  ASSERT_NMATCH("abc^", "abc");
  PASS();
}

TEST(assert_line_begin_afternl)
{
  ASSERT_NMATCH("\n^", "\n");
  PASS();
}

TEST(assert_line_begin_beforenl)
{
  ASSERT_MATCH("^\n", "\n");
  PASS();
}

TEST(assert_line_begin_multiline_empty)
{
  ASSERT_MATCH("(?m)^", "");
  PASS();
}

TEST(assert_line_begin_multiline_beforesome)
{
  ASSERT_MATCH("(?m)^abc", "abc");
  PASS();
}

TEST(assert_line_begin_multiline_aftersome)
{
  ASSERT_NMATCH("(?m)abc^", "abc");
  PASS();
}

TEST(assert_line_begin_multiline_afternl)
{
  ASSERT_MATCH("(?m)\n^", "\n");
  PASS();
}

TEST(assert_line_begin_multiline_beforenl)
{
  ASSERT_MATCH("(?m)^\n", "\n");
  PASS();
}

SUITE(assert_line_begin)
{
  RUN_TEST(assert_line_begin_empty);
  RUN_TEST(assert_line_begin_beforesome);
  RUN_TEST(assert_line_begin_aftersome);
  RUN_TEST(assert_line_begin_afternl);
  RUN_TEST(assert_line_begin_beforenl);
  RUN_TEST(assert_line_begin_multiline_empty);
  RUN_TEST(assert_line_begin_multiline_beforesome);
  RUN_TEST(assert_line_begin_multiline_aftersome);
  RUN_TEST(assert_line_begin_multiline_afternl);
  RUN_TEST(assert_line_begin_multiline_beforenl);
}

TEST(assert_line_end_empty)
{
  ASSERT_MATCH("$", "");
  PASS();
}

TEST(assert_line_end_beforesome)
{
  ASSERT_NMATCH("$abc", "abc");
  PASS();
}

TEST(assert_line_end_aftersome)
{
  ASSERT_MATCH("abc$", "abc");
  PASS();
}

TEST(assert_line_end_afternl)
{
  ASSERT_MATCH("\n$", "\n");
  PASS();
}

TEST(assert_line_end_beforenl)
{
  ASSERT_NMATCH("$\n", "\n");
  PASS();
}

TEST(assert_line_end_multiline_empty)
{
  ASSERT_MATCH("(?m)$", "");
  PASS();
}

TEST(assert_line_end_multiline_beforesome)
{
  ASSERT_NMATCH("(?m)$abc", "abc");
  PASS();
}

TEST(assert_line_end_multiline_aftersome)
{
  ASSERT_MATCH("(?m)abc$", "abc");
  PASS();
}

TEST(assert_line_end_multiline_afternl)
{
  ASSERT_MATCH("(?m)\n$", "\n");
  PASS();
}

TEST(assert_line_end_multiline_beforenl)
{
  ASSERT_MATCH("(?m)$\n", "\n");
  PASS();
}

SUITE(assert_line_end)
{
  RUN_TEST(assert_line_end_empty);
  RUN_TEST(assert_line_end_beforesome);
  RUN_TEST(assert_line_end_aftersome);
  RUN_TEST(assert_line_end_afternl);
  RUN_TEST(assert_line_end_beforenl);
  RUN_TEST(assert_line_end_multiline_empty);
  RUN_TEST(assert_line_end_multiline_beforesome);
  RUN_TEST(assert_line_end_multiline_aftersome);
  RUN_TEST(assert_line_end_multiline_afternl);
  RUN_TEST(assert_line_end_multiline_beforenl);
}

TEST(assert_text_begin_empty)
{
  ASSERT_MATCH("\\A", "");
  PASS();
}

TEST(assert_text_begin_beforesome)
{
  ASSERT_MATCH("\\Aabc", "abc");
  PASS();
}

TEST(assert_text_begin_aftersome)
{
  ASSERT_NMATCH("abc\\A", "abc");
  PASS();
}

TEST(assert_text_begin_afternl)
{
  ASSERT_NMATCH("\n\\A", "\n");
  PASS();
}

TEST(assert_text_begin_beforenl)
{
  ASSERT_MATCH("\\A\n", "\n");
  PASS();
}

TEST(assert_text_begin_multiline_empty)
{
  ASSERT_MATCH("(?m)\\A", "");
  PASS();
}

TEST(assert_text_begin_multiline_beforesome)
{
  ASSERT_MATCH("(?m)\\Aabc", "abc");
  PASS();
}

TEST(assert_text_begin_multiline_aftersome)
{
  ASSERT_NMATCH("(?m)abc\\A", "abc");
  PASS();
}

TEST(assert_text_begin_multiline_afternl)
{
  ASSERT_NMATCH("(?m)\n\\A", "\n");
  PASS();
}

TEST(assert_text_begin_multiline_beforenl)
{
  ASSERT_MATCH("(?m)\\A\n", "\n");
  PASS();
}

SUITE(assert_text_begin)
{
  RUN_TEST(assert_text_begin_empty);
  RUN_TEST(assert_text_begin_beforesome);
  RUN_TEST(assert_text_begin_aftersome);
  RUN_TEST(assert_text_begin_afternl);
  RUN_TEST(assert_text_begin_beforenl);
  RUN_TEST(assert_text_begin_multiline_empty);
  RUN_TEST(assert_text_begin_multiline_beforesome);
  RUN_TEST(assert_text_begin_multiline_aftersome);
  RUN_TEST(assert_text_begin_multiline_afternl);
  RUN_TEST(assert_text_begin_multiline_beforenl);
}

TEST(assert_text_end_empty)
{
  ASSERT_MATCH("\\z", "");
  PASS();
}

TEST(assert_text_end_beforesome)
{
  ASSERT_NMATCH("\\zabc", "abc");
  PASS();
}

TEST(assert_text_end_aftersome)
{
  ASSERT_MATCH("abc\\z", "abc");
  PASS();
}

TEST(assert_text_end_afternl)
{
  ASSERT_MATCH("\n\\z", "\n");
  PASS();
}

TEST(assert_text_end_beforenl)
{
  ASSERT_NMATCH("\\z\n", "\n");
  PASS();
}

TEST(assert_text_end_multiline_empty)
{
  ASSERT_MATCH("(?m)\\z", "");
  PASS();
}

TEST(assert_text_end_multiline_beforesome)
{
  ASSERT_NMATCH("(?m)\\zabc", "abc");
  PASS();
}

TEST(assert_text_end_multiline_aftersome)
{
  ASSERT_MATCH("(?m)abc\\z", "abc");
  PASS();
}

TEST(assert_text_end_multiline_afternl)
{
  ASSERT_MATCH("(?m)\n\\z", "\n");
  PASS();
}

TEST(assert_text_end_multiline_beforenl)
{
  ASSERT_NMATCH("(?m)\\z\n", "\n");
  PASS();
}

SUITE(assert_text_end)
{
  RUN_TEST(assert_text_end_empty);
  RUN_TEST(assert_text_end_beforesome);
  RUN_TEST(assert_text_end_aftersome);
  RUN_TEST(assert_text_end_afternl);
  RUN_TEST(assert_text_end_beforenl);
  RUN_TEST(assert_text_end_multiline_empty);
  RUN_TEST(assert_text_end_multiline_beforesome);
  RUN_TEST(assert_text_end_multiline_aftersome);
  RUN_TEST(assert_text_end_multiline_afternl);
  RUN_TEST(assert_text_end_multiline_beforenl);
}

TEST(assert_word_empty)
{
  ASSERT_NMATCH("\\b", "");
  PASS();
}

TEST(assert_word_beginning_word)
{
  ASSERT_MATCH("\\ba", "a");
  PASS();
}

TEST(assert_word_beginning_notword)
{
  ASSERT_NMATCH("\\b#", "#");
  PASS();
}

TEST(assert_word_end_word)
{
  ASSERT_MATCH("a\\b", "a");
  PASS();
}

TEST(assert_word_end_notword)
{
  ASSERT_NMATCH("#\\b", "#");
  PASS();
}

TEST(assert_word_middle_word)
{
  ASSERT_MATCH("ab\\w\\b\\Wcd", "abZ.cd");
  PASS();
}

TEST(assert_word_middle_notword)
{
  ASSERT_NMATCH("ab\\w\\b\\wcd", "abZacd");
  PASS();
}

SUITE(assert_word)
{
  RUN_TEST(assert_word_empty);
  RUN_TEST(assert_word_beginning_word);
  RUN_TEST(assert_word_beginning_notword);
  RUN_TEST(assert_word_end_word);
  RUN_TEST(assert_word_end_notword);
  RUN_TEST(assert_word_middle_word);
  RUN_TEST(assert_word_middle_notword);
}

TEST(assert_not_word_empty)
{
  ASSERT_MATCH("\\B", "");
  PASS();
}

TEST(assert_not_word_beginning_word)
{
  ASSERT_NMATCH("\\Ba", "a");
  PASS();
}

TEST(assert_not_word_beginning_notword)
{
  ASSERT_MATCH("\\B#", "#");
  PASS();
}

TEST(assert_not_word_end_word)
{
  ASSERT_NMATCH("a\\B", "a");
  PASS();
}

TEST(assert_not_word_end_notword)
{
  ASSERT_MATCH("#\\B", "#");
  PASS();
}

TEST(assert_not_word_middle_word)
{
  ASSERT_NMATCH("ab\\w\\B\\Wcd", "abZ.cd");
  PASS();
}

TEST(assert_not_word_middle_notword)
{
  ASSERT_MATCH("ab\\w\\B\\wcd", "abZacd");
  PASS();
}

SUITE(assert_not_word)
{
  RUN_TEST(assert_not_word_empty);
  RUN_TEST(assert_not_word_beginning_word);
  RUN_TEST(assert_not_word_beginning_notword);
  RUN_TEST(assert_not_word_end_word);
  RUN_TEST(assert_not_word_end_notword);
  RUN_TEST(assert_not_word_middle_word);
  RUN_TEST(assert_not_word_middle_notword);
}

SUITE(assert)
{
  RUN_SUITE(assert_line_begin);
  RUN_SUITE(assert_line_end);
  RUN_SUITE(assert_text_begin);
  RUN_SUITE(assert_text_end);
  RUN_SUITE(assert_word);
  RUN_SUITE(assert_not_word);
}

SUITE(fuzz_regression); /* provided by test-gen.c */

TEST(limit_program_size)
{
  re *r = re_init("a++++++++++++++++++++");
  int err;
  if (!r)
    goto oom;
  if ((err = re_compile(r)) == ERR_MEM)
    goto oom;
  ASSERT_EQ(err, ERR_LIMIT);
  re_destroy(r);
  PASS();
oom:
  re_destroy(r);
  OOM();
}

TEST(limit_dfa_thrash)
{
  /* Cause a DFA cache flush. */
  const char *regex = "a{258}?";
  ASSERT_MATCH(
      regex, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  PASS();
}

SUITE(limits)
{
  RUN_TEST(limit_program_size);
  RUN_TEST(limit_dfa_thrash);
}

int main(int argc, const char *const *argv)
{
  MPTEST_MAIN_BEGIN_ARGS(argc, argv);
  RUN_SUITE(init);
  RUN_SUITE(chr);
  RUN_SUITE(cat);
  RUN_SUITE(quant);
  RUN_SUITE(alt);
  RUN_SUITE(any_byte);
  RUN_SUITE(cls);
  RUN_SUITE(anychar);
  RUN_SUITE(escape);
  RUN_SUITE(repetition);
  RUN_SUITE(grp);
  RUN_SUITE(set);
  RUN_SUITE(assert);
  RUN_SUITE(limits);
#ifndef RE_COV
  /* regression tests should not account for coverage. we should explicitly
   * write tests that fully cover our code, as they are more documentable than
   * potentially cryptic regression tests. */
  RUN_SUITE(fuzz_regression);
#endif
  MPTEST_MAIN_END();
}
