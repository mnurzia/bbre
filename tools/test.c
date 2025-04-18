#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* unfinished: parse string ends early
 * malformed:  parse string contains a malformed utf-8 sequence
 * invalid:    parse string is valid utf-8 but contains an unexpected char */

#include "mptest.h"

#include "../bbre.h"

#ifdef TEST_BULK
  #define TEST_NAMED_CLASS_RANGE_MAX 0x110000
#elif BBRE_COV
  /* to ensure the OOM checker doesn't take a long-ass time */
  #define TEST_NAMED_CLASS_RANGE_MAX 0x1
#else
  #define TEST_NAMED_CLASS_RANGE_MAX 0x80
#endif

#define IMPLIES(c, pred) (!(c) || (pred))

int test_alloc_last_was_null = 0;

size_t utf_encode(char *out_buf, unsigned int codep)
{
  if (codep <= 0x7F) {
    out_buf[0] = codep & 0x7F;
    return 1;
  } else if (codep <= 0x07FF) {
    out_buf[0] = (unsigned char)(((codep >> 6) & 0x1F) | 0xC0);
    out_buf[1] = (unsigned char)(((codep >> 0) & 0x3F) | 0x80);
    return 2;
  } else if (codep <= 0xFFFF) {
    out_buf[0] = (unsigned char)(((codep >> 12) & 0x0F) | 0xE0);
    out_buf[1] = (unsigned char)(((codep >> 6) & 0x3F) | 0x80);
    out_buf[2] = (unsigned char)(((codep >> 0) & 0x3F) | 0x80);
    return 3;
  } else if (codep <= 0x10FFFF) {
    out_buf[0] = (unsigned char)(((codep >> 18) & 0x07) | 0xF0);
    out_buf[1] = (unsigned char)(((codep >> 12) & 0x3F) | 0x80);
    out_buf[2] = (unsigned char)(((codep >> 6) & 0x3F) | 0x80);
    out_buf[3] = (unsigned char)(((codep >> 0) & 0x3F) | 0x80);
    return 4;
  } else {
    assert(0);
    return 0;
  }
}

#define TEST_MAX_SPAN 10
#define TEST_MAX_SET  10

int check_match_api(
    bbre *reg, const char *text, size_t text_size, size_t pos,
    bbre_span *out_captures, unsigned int *out_captures_did_match,
    unsigned int out_captures_size)
{
  if (pos == 0 && !out_captures && !out_captures_did_match &&
      out_captures_size == 0) {
    return bbre_is_match(reg, text, text_size);
  } else if (
      pos == 0 && out_captures && !out_captures_did_match &&
      out_captures_size == 1) {
    return bbre_find(reg, text, text_size, out_captures);
  } else if (
      pos != 0 && out_captures && !out_captures_did_match &&
      out_captures_size == 1) {
    return bbre_find_at(reg, text, text_size, pos, out_captures);
  } else if (
      pos == 0 && out_captures && !out_captures_did_match &&
      out_captures_size > 1) {
    return bbre_captures(reg, text, text_size, out_captures, out_captures_size);
  } else if (
      pos != 0 && out_captures && !out_captures_did_match &&
      out_captures_size > 1) {
    return bbre_captures_at(
        reg, text, text_size, pos, out_captures, out_captures_size);
  } else if (pos == 0 && out_captures && out_captures_did_match) {
    return bbre_which_captures(
        reg, text, text_size, out_captures, out_captures_did_match,
        out_captures_size);
  } else {
    return bbre_which_captures_at(
        reg, text, text_size, pos, out_captures, out_captures_did_match,
        out_captures_size);
  }
}

int check_match_results(
    bbre *r, const char *s, size_t n, unsigned int max_span,
    unsigned int extra_span, bbre_span *check_span, unsigned int *did_match,
    int expected)
{
  int err = 0;
  /* memory for found spans and found sets */
  bbre_span found_span[TEST_MAX_SPAN * TEST_MAX_SET];
  unsigned int found_did_match[TEST_MAX_SPAN];
  unsigned int i, j, k;
  /* run the match twice to ensure that which_captures() and captures() agree */
  for (i = 0; i < 2; i++) {
    for (j = 0;
         j < (1U + (max_span && check_span ? !!check_span[0].begin : 0U));
         j++) {
      memset(found_span, 0xCC, sizeof(found_span));
      memset(found_did_match, 0xCC, sizeof(found_did_match));
      /* perform the match */
      if (!i && (err = check_match_api(
                     r, s, n, j ? check_span[0].begin : 0, found_span,
                     found_did_match, max_span + extra_span)) == BBRE_ERR_MEM)
        OOM();
      else if (
          i && (err = check_match_api(
                    r, s, n, j ? check_span[0].begin : 0, found_span, NULL,
                    max_span + extra_span)) == BBRE_ERR_MEM)
        OOM();
      ASSERT_GTEm(err, 0, "bbre_match() returned an error");
      ASSERT_EQm(err, expected, "bbre_match() didn't return the correct value");
      if (expected) {
        for (k = 0; k < max_span; k++) {
          ASSERT_EQm(
              check_span[k].begin, found_span[k].begin,
              "found unexpected span beginning");
          ASSERT_EQm(
              check_span[k].end, found_span[k].end,
              "found unexpected span end");
          if (!i && did_match)
            ASSERT_EQm(
                did_match[k], found_did_match[k],
                "capture group's match status was wrong");
        }
        for (; k < extra_span; k++)
          if (!i)
            ASSERT_EQm(
                0, found_did_match[k],
                "extra inserted span matched incorrectly");
      }
    }
  }
  PASS();
}

int check_matches_nf(
    const char *regex, size_t regex_n, bbre_flags flags, const char *s,
    size_t n, unsigned int max_span, bbre_span *check_span,
    unsigned int *did_match)
{
  bbre *r = NULL, *r2 = NULL;
  bbre_builder *spec = NULL;
  int err;
  ASSERT_LTEm(max_span, TEST_MAX_SPAN, "too many spans to match");
  if ((err = bbre_builder_init(&spec, regex, regex_n, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQm(err, 0, "bbre_builder_init() returned a nonzero value");
  bbre_builder_flags(spec, flags);
  if ((err = bbre_init(&r, spec, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQm(err, 0, "bbre_init() returned a nonzero value");
  if ((err = check_match_results(
           r, s, n, max_span, 0, check_span, did_match, !!max_span)))
    goto error;
  ASSERT(!err);
  if ((err = check_match_results(
           r, s, n, max_span, 1, check_span, NULL, !!max_span)))
    goto error;
  assert(!err);
  if ((err = check_match_results(
           r, s, n, max_span, 1, check_span, did_match, !!max_span)))
    goto error;
  assert(!err);
  if ((err = check_match_results(r, s, n, 0, 0, NULL, NULL, !!max_span)))
    goto error;
  ASSERT(!err);
  if ((err = check_match_results(
           r, s, n, 1, 0, check_span, did_match, !!max_span)))
    goto error;
  ASSERT(!err);
  if ((err = bbre_clone(&r2, r, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT(!err);
  if ((err = check_match_results(
           r2, s, n, max_span, 0, check_span, did_match, !!max_span)))
    goto error;
  ASSERT(!err);
  if ((err = check_match_results(r2, s, n, 0, 0, NULL, NULL, !!max_span)))
    goto error;
  ASSERT(!err);
error:
  bbre_destroy(r);
  bbre_destroy(r2);
  bbre_builder_destroy(spec);
  return err;
oom:
  bbre_destroy(r);
  bbre_destroy(r2);
  bbre_builder_destroy(spec);
  OOM();
}

int check_matches_n(
    const char *regex, size_t regex_n, const char *s, size_t n,
    unsigned int max_span, bbre_span *check_span, unsigned int *did_match)
{
  return check_matches_nf(
      regex, regex_n, 0, s, n, max_span, check_span, did_match);
}

int check_match(
    const char *regex, const char *s, size_t n, unsigned int max_span,
    bbre_span *check_span, unsigned int *did_match)
{
  size_t regex_n = strlen(regex);
  return check_matches_n(regex, regex_n, s, n, max_span, check_span, did_match);
}

int check_match_f(
    const char *regex, bbre_flags flags, const char *s, size_t n,
    unsigned int max_span, bbre_span *check_span, unsigned int *did_match)
{
  size_t regex_n = strlen(regex);
  return check_matches_nf(
      regex, regex_n, flags, s, n, max_span, check_span, did_match);
}

int check_not_fullmatch_n(const char *regex, const char *s, size_t n)
{
  return check_match(regex, s, n, 0, NULL, 0);
}

int check_not_fullmatch(const char *regex, const char *s)
{
  return check_not_fullmatch_n(regex, s, strlen(s));
}

int check_match_g1_n(
    const char *regex, const char *s, size_t n, size_t b, size_t e)
{
  bbre_span g;
  unsigned int did = 1;
  g.begin = b, g.end = e;
  return check_match(regex, s, n, 1, &g, &did);
}

int check_match_g1(const char *regex, const char *s, size_t b, size_t e)
{
  return check_match_g1_n(regex, s, strlen(s), b, e);
}

int check_match_g1_nf(
    const char *regex, bbre_flags flags, const char *s, size_t n, size_t b,
    size_t e)
{
  bbre_span g;
  unsigned int did = 1;
  g.begin = b, g.end = e;
  return check_match_f(regex, flags, s, n, 1, &g, &did);
}

int check_match_g1_f(
    const char *regex, bbre_flags flags, const char *s, size_t b, size_t e)
{
  return check_match_g1_nf(regex, flags, s, strlen(s), b, e);
}

int check_match_g2(
    const char *regex, const char *s, size_t b, size_t e, size_t b2, size_t e2)
{
  bbre_span g[2];
  unsigned int did[2] = {1, 1};
  g[0].begin = b, g[0].end = e;
  g[1].begin = b2, g[1].end = e2;
  return check_match(regex, s, strlen(s), 2, g, did);
}

int check_fullmatch_n(const char *regex, const char *s, size_t n)
{
  return check_match_g1_n(regex, s, n, 0, n);
}

int check_fullmatch(const char *regex, const char *s)
{
  return check_fullmatch_n(regex, s, strlen(s));
}

#define ASSERT_MATCH(regex, str)  PROPAGATE(check_fullmatch(regex, str))
#define ASSERT_NMATCH(regex, str) PROPAGATE(check_not_fullmatch(regex, str))
#define ASSERT_MATCH_N(regex, str, sz)                                         \
  PROPAGATE(check_fullmatch_n(regex, str, sz));
#define ASSERT_NMATCH_N(regex, str, sz)                                        \
  PROPAGATE(check_not_fullmatch_n(regex, str, sz));
#define ASSERT_MATCH_G1(regex, str, b, e)                                      \
  PROPAGATE(check_match_g1(regex, str, b, e))
#define ASSERT_MATCH_G1_F(regex, flags, str, b, e)                             \
  PROPAGATE(check_match_g1_f(regex, flags, str, b, e))
#define ASSERT_MATCH_G2(regex, str, b, e, b2, e2)                              \
  PROPAGATE(check_match_g2(regex, str, b, e, b2, e2))

int check_noparse_n(
    const char *regex, size_t n, const char *err_msg, size_t err_msg_pos)
{
  bbre *r = NULL;
  bbre_builder *spec = NULL;
  int err;
  if ((err = bbre_builder_init(&spec, regex, n, NULL)) == BBRE_ERR_MEM)
    goto oom;
  if ((err = bbre_init(&r, spec, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, BBRE_ERR_PARSE);
  ASSERT(!strcmp(err_msg, bbre_get_err_msg(r)));
  ASSERT_EQ(err_msg_pos, bbre_get_err_pos(r));
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  PASS();
oom:
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  OOM();
}

int check_noparse(const char *regex, const char *err_msg, size_t err_msg_pos)
{
  PROPAGATE(check_noparse_n(regex, strlen(regex), err_msg, err_msg_pos));
  PASS();
}

#define ASSERT_NOPARSE(regex, err_msg, pos)                                    \
  PROPAGATE(check_noparse(regex, err_msg, pos))

int check_compiles_n(const char *regex, size_t n)
{
  bbre *r = NULL;
  bbre_builder *spec = NULL;
  int err;
  if ((err = bbre_builder_init(&spec, regex, n, NULL)) == BBRE_ERR_MEM)
    goto oom;
  if ((err = bbre_init(&r, spec, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, 0);
  if ((err = bbre_is_match(r, "", 0)) == BBRE_ERR_MEM)
    goto oom;
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  PASS();
oom:
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  OOM();
}

int check_compiles(const char *regex)
{
  PROPAGATE(check_compiles_n(regex, strlen(regex)));
  PASS();
}

unsigned int matchnum(const char *num)
{
  unsigned int out = 0;
  unsigned char chout;
  if (sscanf(num, "0x%X", &out))
    return out;
  else if (sscanf(num, "%c", &chout))
    return chout;
  else
    assert(0);
  return 0;
}

unsigned int matchspec(const char *spec, unsigned int *ranges)
{
  unsigned int n = 0;
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
    ranges[0] = ranges[1] = matchnum(tmp_buf);
    if (space < comma) {
      memset(tmp_buf, 0, sizeof tmp_buf);
      memcpy(tmp_buf, space + 1, comma - space);
      ranges[1] = matchnum(tmp_buf);
    }
    spec = nextspec, ranges += 2, n++;
  }
  return n;
}

int assert_cc_match_raw(
    const char *regex, const unsigned int *ranges, unsigned int num_ranges,
    int invert)
{
  bbre *r = NULL;
  bbre_builder *spec = NULL;
  int err;
  unsigned int codep, range_idx;
  char utf8[16];
  if ((err = bbre_builder_init(&spec, regex, strlen(regex), NULL)) ==
      BBRE_ERR_MEM)
    goto oom;
  if ((err = bbre_init(&r, spec, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT(!err);
  for (codep = 0; codep < TEST_NAMED_CLASS_RANGE_MAX; codep++) {
    size_t sz = utf_encode(utf8, codep);
    if ((err = bbre_is_match(r, utf8, sz)) == BBRE_ERR_MEM)
      goto oom;
    for (range_idx = 0; range_idx < num_ranges; range_idx++) {
      if (codep >= ranges[range_idx * 2] &&
          codep <= ranges[range_idx * 2 + 1]) {
        ASSERT_EQ(err, !invert);
        break;
      }
    }
    if (range_idx == num_ranges) {
      if ((err = bbre_is_match(r, utf8, sz)) == BBRE_ERR_MEM)
        goto oom;
      ASSERT_EQ(err, invert);
    }
  }
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  PASS();
oom:
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  OOM();
}

int assert_cc_match(const char *regex, const char *spec, int invert)
{
  unsigned int ranges[128];
  unsigned int nrange = matchspec(spec, ranges);
  PROPAGATE(assert_cc_match_raw(regex, ranges, nrange, invert));
  PASS();
}

#define ASSERT_CC_MATCH(regex, spec) PROPAGATE(assert_cc_match(regex, spec, 0))

TEST(init_empty)
{
  /* init should initialize the regular expression or return NULL on OOM */
  bbre *r = bbre_init_pattern("");
  if (!r && test_alloc_last_was_null)
    OOM();
  bbre_destroy(r);
  PASS();
}

TEST(init_some)
{
  bbre *r = bbre_init_pattern("a");
  if (!r && test_alloc_last_was_null)
    OOM();
  bbre_destroy(r);
  PASS();
}

extern void *
bbre_default_alloc(void *user, void *ptr, size_t prev, size_t next);

TEST(init_full_default_alloc)
{
  bbre *r = NULL;
  bbre_builder *spec = NULL;
  int err;
  bbre_alloc alloc;
  alloc.user = NULL;
  alloc.cb = bbre_default_alloc;
  if ((err = bbre_builder_init(&spec, "abc", 3, &alloc)) == BBRE_ERR_MEM)
    goto oom;
  if ((err = bbre_init(&r, spec, &alloc)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, 0);
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  PASS();
oom:
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  OOM();
}

TEST(init_bad)
{
  bbre *r = bbre_init_pattern("\xff");
  ASSERT_EQ(r, NULL);
  if (test_alloc_last_was_null)
    OOM();
  PASS();
}

TEST(init_flag_insensitive)
{
  ASSERT_MATCH_G1_F("A", BBRE_FLAG_INSENSITIVE, "a", 0, 1);
  PASS();
}

TEST(init_flag_multiline)
{
  ASSERT_MATCH_G1_F("^A$", BBRE_FLAG_MULTILINE, "a\nA\n", 2, 3);
  PASS();
}

TEST(init_flag_dotnewline)
{
  ASSERT_MATCH_G1_F(".", BBRE_FLAG_DOTNEWLINE, "\n", 0, 1);
  PASS();
}

TEST(init_flag_ungreedy)
{
  ASSERT_MATCH_G1_F("A*", BBRE_FLAG_UNGREEDY, "AA", 0, 0);
  PASS();
}

SUITE(init_flag)
{
  RUN_TEST(init_flag_insensitive);
  RUN_TEST(init_flag_multiline);
  RUN_TEST(init_flag_dotnewline);
  RUN_TEST(init_flag_ungreedy);
}

SUITE(init)
{
  RUN_TEST(init_empty);
  RUN_TEST(init_some);
  RUN_TEST(init_bad);
  RUN_TEST(init_full_default_alloc);
  RUN_SUITE(init_flag);
}

TEST(chr_1)
{
  ASSERT_MATCH("a", "a");
  PASS();
}

TEST(chr_2)
{
  ASSERT_MATCH("\xd4\x80", "\xd4\x80");
  PASS();
}

TEST(chr_3)
{
  ASSERT_MATCH("\xe2\x98\x85", "\xe2\x98\x85");
  PASS();
}

TEST(chr_4)
{
  ASSERT_MATCH("\xf0\x9f\xa4\xa0", "\xf0\x9f\xa4\xa0");
  PASS();
}

TEST(chr_malformed)
{
  ASSERT_NOPARSE("\xff", "invalid utf-8 sequence", 0);
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
  ASSERT_MATCH("ab", "ab");
  PASS();
}

TEST(cat_double)
{
  ASSERT_MATCH("abc", "abc");
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
  ASSERT_MATCH_G2("(a*)", "aa", 0, 2, 0, 2);
  PASS();
}

TEST(star_ungreedy)
{
  ASSERT_MATCH_G2("(a*?)", "aa", 0, 0, 0, 0);
  PASS();
}

TEST(star_greedy_then_ungreedy)
{
  ASSERT_MATCH_G2("a*(a*?)", "aaaaaa", 0, 6, 6, 6);
  PASS();
}

TEST(star_ungreedy_then_greedy)
{
  ASSERT_MATCH_G2("a*?(a*)", "aaaaaa", 0, 6, 0, 6);
  PASS();
}

TEST(star_ungreedy_with_assert)
{
  ASSERT_MATCH_G2("(a*?)\\b a*", "a a b", 0, 3, 0, 1);
  PASS();
}

TEST(star_ungreedy_with_assert_unanchored)
{
  ASSERT_MATCH_G2("(a*?)\\b a*", "lauaaa a", 3, 8, 3, 6);
  PASS();
}

TEST(star_greedy_end_anchored)
{
  ASSERT_MATCH_G1("A*$", "aAAA", 1, 4);
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
  RUN_TEST(star_greedy_end_anchored);
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
  ASSERT_NMATCH("^a?$", "aa");
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
  ASSERT_NOPARSE("*", "cannot apply quantifier to empty regex", 1);
  PASS();
}

TEST(quant_ungreedy_malformed)
{
  ASSERT_NOPARSE("b*\xff", "invalid utf-8 sequence", 2);
  PASS();
}

TEST(quant_nested_epsilon_group)
{
  ASSERT_MATCH_G2("(?:(a*))*", "", 0, 0, 0, 0);
  PASS();
}

TEST(quant_duplicated_nested)
{
  ASSERT_MATCH("(?:a*){3,}", "aaaaaa");
  PASS();
}

TEST(quant_duplicated_nested_nested)
{
  ASSERT_MATCH("(?:a**){3,}", "aaaaaa");
  PASS();
}

TEST(quant_zero_nested)
{
  ASSERT_MATCH_G2("(a{0}){0,2}", "", 0, 0, 0, 0);
  PASS();
}

SUITE(quant)
{
  RUN_SUITE(star);
  RUN_SUITE(quest);
  RUN_SUITE(plus);
  RUN_TEST(quant_of_nothing);
  RUN_TEST(quant_ungreedy_malformed);
  RUN_TEST(quant_nested_epsilon_group);
  RUN_TEST(quant_duplicated_nested);
  RUN_TEST(quant_duplicated_nested_nested);
  RUN_TEST(quant_zero_nested);
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
  ASSERT_MATCH_G1("|a", "a", 0, 0);
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

TEST(alt_nevermatch)
{
  ASSERT_MATCH("|[^\\x00-\\x{10FFFF}]", "");
  PASS();
}

TEST(alt_captures_only_half_in_epsilon)
{
  const char *regex = ".*|(.*)";
  bbre_span check_span[2] = {
      {0, 0},
      {0, 0},
  };
  unsigned int check_did_match[2] = {1, 0};
  PROPAGATE(check_matches_n(
      regex, strlen(regex), "", 0, 2, check_span, check_did_match));
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
  RUN_TEST(alt_nevermatch);
  RUN_TEST(alt_captures_only_half_in_epsilon);
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

TEST(anychar_aftersome)
{
  ASSERT_MATCH("a.", "aa");
  PASS();
}

SUITE(anychar)
{
  RUN_TEST(anychar_unicode_1);
  RUN_TEST(anychar_unicode_2);
  RUN_TEST(anychar_unicode_3);
  RUN_TEST(anychar_unicode_4);
  RUN_TEST(anychar_unicode_malformed);
  RUN_TEST(anychar_aftersome);
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
  ASSERT_NOPARSE("[\\C]", "cannot use \\C here", 3);
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
  ASSERT_NOPARSE("[\\Qabc\\E]", "cannot use \\Q...\\E here", 3);
  PASS();
}

TEST(cls_escape_quote_range_end)
{
  ASSERT_NOPARSE("[a-\\Qabc\\E]", "cannot use \\Q...\\E here", 5);
  PASS();
}

TEST(cls_escape_cls_after_some)
{
  ASSERT_MATCH(
      "a["
      "abcdef\\d\\D\\s\\S\\d\\D\\s\\S\\PL\\PC\\w\\W\\w\\W\\w\\W\\w\\W\\w\\W\\w"
      "\\W\\"
      "w]",
      "aa");
  PASS();
}

SUITE(cls_escape)
{
  RUN_TEST(cls_escape_any_byte);
  RUN_TEST(cls_escape_single);
  RUN_TEST(cls_escape_range_start);
  RUN_TEST(cls_escape_range_end);
  RUN_TEST(cls_escape_range_both);
  RUN_TEST(cls_escape_quote);
  RUN_TEST(cls_escape_quote_range_end);
  RUN_TEST(cls_escape_cls_after_some);
}

TEST(cls_empty)
{
  ASSERT_NOPARSE("[]", "unclosed character class", 2);
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
  ASSERT_NOPARSE("[[", "unclosed character class", 2);
  PASS();
}

TEST(cls_left_bracket_malformed)
{
  ASSERT_NOPARSE("[[\xff", "invalid utf-8 sequence", 2);
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

TEST(cls_single_inverted)
{
  ASSERT_CC_MATCH("[^a]", "0x0 0x60,0x62 0x10FFFF");
  PASS();
}

TEST(cls_inverted_aftersome)
{
  ASSERT_MATCH("a[^a]", "ab");
  PASS();
}

TEST(cls_single_malformed)
{
  ASSERT_NOPARSE("[a\xff]", "invalid utf-8 sequence", 2);
  PASS();
}

TEST(cls_single_unfinished)
{
  ASSERT_NOPARSE("[a", "unclosed character class", 2);
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
  ASSERT_NOPARSE("[a-]", "unclosed character class", 4);
  PASS();
}

TEST(cls_range_one_malformed)
{
  ASSERT_NOPARSE("[a-\xff]", "invalid utf-8 sequence", 3);
  PASS();
}

TEST(cls_ending_dash)
{
  ASSERT_CC_MATCH("[-]", "-");
  PASS();
}

TEST(cls_ending_dash_unfinished)
{
  ASSERT_NOPARSE(
      "[a-",
      "expected ']' or ending character after '-' for character class range "
      "expression",
      3);
  PASS();
}

TEST(cls_named_unfinished)
{
  ASSERT_NOPARSE("[[:", "expected character class name", 3);
  PASS();
}

TEST(cls_named_malformed)
{
  ASSERT_NOPARSE("[[:\xff", "invalid utf-8 sequence", 3);
  PASS();
}

TEST(cls_named_unfinished_aftername)
{
  ASSERT_NOPARSE("[[:alnum", "expected character class name", 8);
  PASS();
}

TEST(cls_named_unfinished_aftercolon)
{
  ASSERT_NOPARSE(
      "[[:alnum:", "expected closing bracket for named character class", 9);
  PASS();
}

TEST(cls_named_invalid_norightbracket)
{
  ASSERT_NOPARSE(
      "[[:alnum:p", "expected closing bracket for named character class", 10);
  PASS();
}

TEST(cls_named_unknown)
{
  ASSERT_NOPARSE("[[:unknown:]]", "invalid Unicode property name", 12);
  PASS();
}

TEST(cls_named_simple)
{
  ASSERT_CC_MATCH("[[:alnum:]]", "0x30 0x39,0x41 0x5A,0x61 0x7A");
  PASS();
}

TEST(cls_named_inverted_aftersome)
{
  ASSERT_MATCH("a[[:^alnum:]]", "a%");
  PASS();
}

TEST(cls_insensitive)
{
  ASSERT_CC_MATCH("(?i:[a])", "a a,A A");
  PASS();
}

TEST(cls_insensitive_small_range)
{
  ASSERT_CC_MATCH("(?i:[A-B])", "A B,a b");
  PASS();
}

TEST(cls_subclass)
{
  ASSERT_CC_MATCH("[\\w]", "0x30 0x39,0x41 0x5A,0x5F 0x5F,0x61 0x7A");
  PASS();
}

TEST(cls_subclass_range_end)
{
  ASSERT_NOPARSE("[a-\\w]", "cannot use a character class here", 5);
  PASS();
}

TEST(cls_unicode_property)
{
  ASSERT_CC_MATCH("[\\p{Cc}]", "0x0 0x1F,0x7F 0x9F");
  PASS();
}

TEST(cls_unicode_property_inverted)
{
  ASSERT_CC_MATCH("[\\P{Cc}]", "0x20 0x7E,0xA0 0x10FFFF");
  PASS();
}

TEST(cls_unicode_property_range_end)
{
  ASSERT_NOPARSE("[a-\\p{Cc}]", "cannot use a character class here", 9);
  PASS();
}

TEST(cls_nevermatch)
{
  ASSERT_NMATCH("[^\\x00-\\x{10FFFF}]", "a");
  PASS();
}

TEST(cls_nevermatch_first)
{
  ASSERT_NMATCH("[^\\x00-\\x{10FFFF}]", "a");
  PASS();
}

TEST(cls_reversed)
{
  ASSERT_CC_MATCH("[Z-A]", "A Z");
  PASS();
}

TEST(cls_reversed_nonmatch)
{
  ASSERT_NMATCH("[Z-A]", ",");
  PASS();
}

TEST(cls_assert)
{
  ASSERT_NOPARSE("[\\A]", "cannot use an epsilon assertion here", 3);
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

TEST(cls_utf8_insensitive_posix)
{
  ASSERT_CC_MATCH("(?i)[[:alpha:]]", "A Z,a z");
  PASS();
}

TEST(cls_utf8_insensitive_inverted)
{
  ASSERT_CC_MATCH("(?i)[^BDF]", "0 A,C C,E E,G a,c c,e e,g 0x10FFFF");
  PASS();
}

TEST(cls_utf8_ranges_common_first_bytes)
{
  /* narrows down a very specific crash found by fuzzington (0017) */
  ASSERT_CC_MATCH(
      "[\\x09-\\x41\\x{164}-\\x{4c6e6}\\x{5927a}-\\x{5e0b7}\\x{6bef8}-\\x{"
      "b285e}]",
      "0x9 0x41,0x164 0x4C6E6,0x5927A 0x5E0B7,0x6BEF8 0xB285E");
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
  RUN_TEST(cls_utf8_insensitive_posix);
  RUN_TEST(cls_utf8_insensitive_inverted);
  RUN_TEST(cls_utf8_ranges_common_first_bytes);
}

SUITE(cls_builtin);                   /* provided by test-gen.c */
SUITE(cls_insensitive_foldrange_arr); /* provided by test-gen.c */

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
  RUN_TEST(cls_single_inverted);
  RUN_TEST(cls_single_malformed);
  RUN_TEST(cls_single_unfinished);
  RUN_TEST(cls_inverted_aftersome);
  RUN_TEST(cls_range_one);
  RUN_TEST(cls_range_one_inverted);
  RUN_TEST(cls_range_one_unfinished);
  RUN_TEST(cls_range_one_malformed);
  RUN_TEST(cls_ending_dash);
  RUN_TEST(cls_ending_dash_unfinished);
  RUN_TEST(cls_named_unfinished);
  RUN_TEST(cls_named_malformed);
  RUN_TEST(cls_named_unfinished_aftername);
  RUN_TEST(cls_named_unfinished_aftercolon);
  RUN_TEST(cls_named_invalid_norightbracket);
  RUN_TEST(cls_named_unknown);
  RUN_TEST(cls_named_simple);
  RUN_TEST(cls_named_inverted_aftersome);
  RUN_TEST(cls_insensitive);
  RUN_TEST(cls_insensitive_small_range);
  RUN_TEST(cls_subclass);
  RUN_TEST(cls_subclass_range_end);
  RUN_TEST(cls_unicode_property);
  RUN_TEST(cls_unicode_property_inverted);
  RUN_TEST(cls_unicode_property_range_end);
  RUN_TEST(cls_nevermatch);
  RUN_TEST(cls_nevermatch_first);
  RUN_TEST(cls_reversed);
  RUN_TEST(cls_reversed_nonmatch);
  RUN_TEST(cls_assert);
  RUN_SUITE(cls_utf8);
  RUN_SUITE(cls_builtin);
  RUN_SUITE(cls_insensitive_foldrange_arr);
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

TEST(escape_dot)
{
  ASSERT_MATCH("\\.", ".");
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
  ASSERT_NOPARSE("\\1\xff", "invalid utf-8 sequence", 2);
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
  ASSERT_NOPARSE(
      "\\x", "expected two hex characters or a bracketed hex literal", 2);
  PASS();
}

TEST(escape_hex_unfinished_1)
{
  ASSERT_NOPARSE("\\x1", "expected two hex characters", 3);
  PASS();
}

TEST(escape_hex_malformed)
{
  ASSERT_NOPARSE("\\x\xff", "invalid utf-8 sequence", 2);
  PASS();
}

TEST(escape_hex_malformed_1)
{
  ASSERT_NOPARSE("\\x1\xff", "invalid utf-8 sequence", 3);
  PASS();
}

TEST(escape_hex_invalid)
{
  ASSERT_NOPARSE("\\xx", "invalid hex digit", 3);
  PASS();
}

TEST(escape_hex_invalid_1)
{
  ASSERT_NOPARSE("\\x1x", "invalid hex digit", 4);
  PASS();
}

TEST(escape_hex_invalid_2)
{
  ASSERT_NOPARSE("\\x/", "invalid hex digit", 3);
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
  ASSERT_NOPARSE("\\x{", "expected up to six hex characters", 3);
  PASS();
}

TEST(escape_hex_long_unfinished_aftersome)
{
  ASSERT_NOPARSE("\\x{1", "expected up to six hex characters", 4);
  PASS();
}

TEST(escape_hex_long_too_long)
{
  /* bracketed hex literals should only be up to six characters */
  ASSERT_NOPARSE("\\x{1000000}", "expected up to six hex characters", 10);
  PASS();
}

TEST(escape_hex_long_out_of_range)
{
  /* bracketed hex literals should not be greater than 0x10FFFF */
  ASSERT_NOPARSE("\\x{110000}", "ordinal value out of range [0, 0x10FFFF]", 10);
  PASS();
}

TEST(escape_hex_long_invalid)
{
  ASSERT_NOPARSE("\\x{&&}", "invalid hex digit", 4);
  PASS();
}

TEST(escape_hex_long_empty)
{
  ASSERT_NOPARSE("\\x{}", "expected at least one hex character", 4);
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
  ASSERT_NOPARSE("\\Q\xff", "invalid utf-8 sequence", 2);
  PASS();
}

TEST(escape_quote_malformed_afterslash)
{
  ASSERT_NOPARSE("\\Q\\\xff", "invalid utf-8 sequence", 3);
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

TEST(escape_unicode_property_simple)
{
  ASSERT_CC_MATCH("\\p{Cc}", "0x0 0x1F,0x7F 0x9F");
  PASS();
}

TEST(escape_unicode_property_inverted_simple)
{
  PROPAGATE(assert_cc_match("\\P{Cc}", "0x0 0x1F,0x7F 0x9F", 1));
  PASS();
}

TEST(escape_unicode_property_complex)
{
  /* tests memory allocation corner cases, this is somewhat bad practice */
  ASSERT_MATCH("ae\\PCdef", "aefdef");
  PASS();
}

TEST(escape_unicode_property_unfinished)
{
  ASSERT_NOPARSE(
      "\\p",
      "expected one-character property name or bracketed property name "
      "for Unicode property escape",
      2);
  PASS();
}

TEST(escape_unicode_property_bracketed_unfinished)
{
  ASSERT_NOPARSE("\\p{", "expected '}' to close bracketed property name", 3);
  PASS();
}

TEST(escape_unfinished)
{
  ASSERT_NOPARSE("\\", "expected escape sequence", 1);
  PASS();
}

TEST(escape_invalid)
{
  ASSERT_NOPARSE("\\/", "invalid escape sequence", 2);
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
  RUN_TEST(escape_dot);
  RUN_SUITE(escape_octal);
  RUN_SUITE(escape_hex);
  RUN_SUITE(escape_hex_long);
  RUN_TEST(escape_any_byte);
  RUN_SUITE(escape_quote);
  RUN_TEST(escape_unfinished);
  RUN_TEST(escape_invalid);
  RUN_TEST(escape_unicode_property_simple);
  RUN_TEST(escape_unicode_property_inverted_simple);
  RUN_TEST(escape_unicode_property_complex);
  RUN_TEST(escape_unicode_property_unfinished);
  RUN_TEST(escape_unicode_property_bracketed_unfinished);
}

TEST(repetition_zero_empty)
{
  ASSERT_MATCH("a{0}", "");
  PASS();
}

TEST(repetition_zero_one)
{
  ASSERT_NMATCH("^a{0}$", "a");
  PASS();
}

TEST(repetition_zero_two)
{
  ASSERT_NMATCH("^a{0}$", "aa");
  PASS();
}

TEST(repetition_zero_nonmatch)
{
  ASSERT_NMATCH("^a{0}$", "b");
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
  ASSERT_NMATCH("^a{1}$", "aa");
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
  ASSERT_NMATCH("^a{2}$", "aaa");
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
  ASSERT_NMATCH("^a{0,}$$", "b");
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
  ASSERT_NMATCH("^a{1,3}$", "aaaa");
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
  ASSERT_NMATCH("^a{0,0}$", "aa");
  PASS();
}

TEST(repetition_malformed)
{
  ASSERT_NOPARSE("a{\xff}", "invalid utf-8 sequence", 2);
  PASS();
}

TEST(repetition_malformed_afterdigit)
{
  ASSERT_NOPARSE("a{1\xff}", "invalid utf-8 sequence", 3);
  PASS();
}

TEST(repetition_unfinished)
{
  ASSERT_NOPARSE("a{", "expected at least one decimal digit", 2);
  PASS();
}

TEST(repetition_unfinished_afterdigit)
{
  ASSERT_NOPARSE("a{1", "expected } to end repetition expression", 3);
  PASS();
}

TEST(repetition_nomin)
{
  ASSERT_NOPARSE("a{,", "expected at least one decimal digit", 2);
  PASS();
}

TEST(repetition_toomanydigits)
{
  ASSERT_NOPARSE(
      "a{123412341234123412341234}", "too many digits for decimal number", 8);
  PASS();
}

TEST(repetition_empty)
{
  ASSERT_NOPARSE("a{}", "expected at least one decimal digit", 2);
  PASS();
}

TEST(repetition_upper_unfinished)
{
  ASSERT_NOPARSE(
      "w{5,", "expected upper bound or } to end repetition expression", 4);
  PASS();
}

TEST(repetition_upper_malformed)
{
  ASSERT_NOPARSE("l{5,\xff}", "invalid utf-8 sequence", 4);
  PASS();
}

TEST(repetition_upper_unfinished_afternumber)
{
  ASSERT_NOPARSE("j{100,5", "expected } to end repetition expression", 7);
  PASS();
}

TEST(repetition_upper_malformed_afternumber)
{
  ASSERT_NOPARSE("q{100,5\xff}", "invalid utf-8 sequence", 7);
  PASS();
}

TEST(repetition_upper_invalid_afternumber)
{
  ASSERT_NOPARSE("w{97,677a}", "expected } to end repetition expression", 9);
  PASS();
}

TEST(repetition_upper_invalid)
{
  ASSERT_NOPARSE("9{5,5223222111}", "too many digits for decimal number", 10);
  PASS();
}

TEST(repetition_upper_badsep)
{
  ASSERT_NOPARSE("p{5a11}", "expected } or , for repetition expression", 4);
  PASS();
}

TEST(repetition_empty_regex)
{
  ASSERT_NOPARSE("{2,3}", "cannot apply quantifier to empty regex", 1);
  PASS();
}

TEST(repetition_many)
{
  ASSERT_MATCH("a{2,3}b{10,20}c{1,2}d{3,5}", "aabbbbbbbbbbbbbbbccdddd");
  PASS();
}

TEST(repetition_epsilon_zero_one)
{
  ASSERT_MATCH("(?:a{0,0}a{0,0}|a){0,1}", "");
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
  RUN_TEST(repetition_nomin);
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
  RUN_TEST(repetition_epsilon_zero_one);
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
  ASSERT_MATCH_G1("(?u)a*", "aa", 0, 0);
  PASS();
}

TEST(grp_flag_u_nmatch)
{
  ASSERT_NMATCH("(?u)a+", "b");
  PASS();
}

TEST(grp_flag_u_off_match)
{
  ASSERT_MATCH_G1("(?u:(?-u:a*))", "aa", 0, 2);
  PASS();
}

TEST(grp_flag_u_off_nmatch)
{
  ASSERT_NMATCH("^(?u:(?-u:a*))$", "b");
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
  ASSERT_NOPARSE("(?<name", "expected name followed by '>' for named group", 7);
  PASS();
}

TEST(grp_named_regular_malformed_before_name)
{
  ASSERT_NOPARSE("(?\xff", "invalid utf-8 sequence", 2);
  PASS();
}

TEST(grp_named_regular_malformed)
{
  ASSERT_NOPARSE("(?<name\xff", "invalid utf-8 sequence", 7);
  PASS();
}

TEST(grp_named_perl)
{
  ASSERT_MATCH("(?P<name>a)", "a");
  PASS();
}

TEST(grp_named_perl_unfinished_before_name)
{
  ASSERT_NOPARSE("(?P", "expected '<' after named group opener \"(?P\"", 3);
  PASS();
}

TEST(grp_named_perl_malformed_before_name)
{
  ASSERT_NOPARSE("(?P\xff", "invalid utf-8 sequence", 3);
  PASS();
}

TEST(grp_named_perl_unfinished)
{
  ASSERT_NOPARSE(
      "(?P<name", "expected name followed by '>' for named group", 8);
  PASS();
}

TEST(grp_named_perl_malformed)
{
  ASSERT_NOPARSE("(?P<name\xff", "invalid utf-8 sequence", 8);
  PASS();
}

TEST(grp_named_perl_invalid)
{
  ASSERT_MATCH("(?P<name>a)", "a");
  PASS();
}

TEST(grp_named_perl_invalid_before_name)
{
  ASSERT_NOPARSE("(?Pl", "expected '<' after named group opener \"(?P\"", 4);
  PASS();
}

TEST(grp_named_check_count_names)
{
  bbre *r = bbre_init_pattern("(?<test>AAA)|(?<abcdef>[6]*)");
  const char *names[4], *names_nt[4];
  size_t names_size[4];
  size_t i = 0;
  /* ensure that these vars actually get written to */
  memset(names, 0xCC, sizeof(names));
  memset(names_nt, 0xCC, sizeof(names_nt));
  memset(names_size, 0xCC, sizeof(names_size));
  if (!r && test_alloc_last_was_null)
    OOM();
  ASSERT_NEQ(r, NULL);
  ASSERT_EQ(bbre_capture_count(r), 3);
  for (i = 0; i < 4; i++) {
    names[i] = bbre_capture_name(r, i, &names_size[i]);
    names_nt[i] = bbre_capture_name(r, i, NULL);
  }
  ASSERT(!strcmp(names[0], ""));
  ASSERT(!strcmp(names_nt[0], ""));
  ASSERT_EQ(names_size[0], 0);
  ASSERT(!strcmp(names[1], "test"));
  ASSERT(!strcmp(names_nt[1], "test"));
  ASSERT_EQ(names_size[1], 4);
  ASSERT(!strcmp(names[2], "abcdef"));
  ASSERT(!strcmp(names_nt[2], "abcdef"));
  ASSERT_EQ(names_size[2], 6);
  ASSERT_EQ(names[3], NULL);
  ASSERT_EQ(names_nt[3], 0);
  bbre_destroy(r);
  PASS();
}

SUITE(grp_named)
{
  RUN_TEST(grp_named_regular);
  RUN_TEST(grp_named_regular_unfinished);
  RUN_TEST(grp_named_regular_malformed);
  RUN_TEST(grp_named_regular_malformed_before_name);
  RUN_TEST(grp_named_perl_unfinished_before_name);
  RUN_TEST(grp_named_perl_malformed);
  RUN_TEST(grp_named_perl_malformed_before_name);
  RUN_TEST(grp_named_perl);
  RUN_TEST(grp_named_perl_unfinished);
  RUN_TEST(grp_named_perl_invalid);
  RUN_TEST(grp_named_perl_invalid_before_name);
  RUN_TEST(grp_named_check_count_names);
}

TEST(grp_unfinished)
{
  ASSERT_NOPARSE("(", "expected ')' to close group", 1);
  PASS();
}

TEST(grp_unfinished_afterspecial)
{
  ASSERT_NOPARSE(
      "(?",
      "expected 'P', '<', or group flags after special group opener \"(?\"", 2);
  PASS();
}

TEST(grp_unfinished_afterflag)
{
  ASSERT_NOPARSE(
      "(?i", "expected ':', ')', or group flags for special group", 3);
  PASS();
}

TEST(grp_malformed)
{
  ASSERT_NOPARSE("(\xff", "invalid utf-8 sequence", 1);
  PASS();
}

TEST(grp_empty)
{
  ASSERT_MATCH_G2("()", "", 0, 0, 0, 0);
  PASS();
}

TEST(grp_nonmatching_unfinished)
{
  ASSERT_NOPARSE(
      "(?",
      "expected 'P', '<', or group flags after special group opener \"(?\"", 2);
  PASS();
}

TEST(grp_nonmatching_malformed)
{
  ASSERT_NOPARSE("(?\xff", "invalid utf-8 sequence", 2);
  PASS();
}

TEST(grp_nonmatching_in_zero_quant)
{
  ASSERT_MATCH("(?:){0,0}", "");
  PASS();
}

TEST(grp_negate_twice)
{
  ASSERT_NOPARSE("(?--:)", "cannot apply flag negation '-' twice", 4);
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
  const char *regex = "(?u)abc";
  bbre_span spans[2] = {
      {0, 3},
      {0, 0}
  };
  unsigned int did_match[2] = {1, 0};
  /* inline flags shouldn't cause groups to be set */
  PROPAGATE(
      check_matches_n(regex, strlen(regex), "abc", 3, 2, spans, did_match));
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
  ASSERT_NOPARSE(
      "(?x)", "expected ':', ')', or group flags for special group", 3);
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

TEST(grp_nested_inlines_resetting)
{
  ASSERT_NMATCH("(?i)(a(?-i)A)a", "AaA");
  PASS();
}

TEST(grp_invalid_unmatched_rparen)
{
  ASSERT_NOPARSE(")", "extra close parenthesis", 1);
  PASS();
}

TEST(grp_invalid_unmatched_lparen)
{
  ASSERT_NOPARSE("(abc", "unmatched open parenthesis", 4);
  PASS();
}

TEST(grp_nested_in_nonmatching)
{
  ASSERT_MATCH_G2("(?:(A))", "A", 0, 1, 0, 1);
  PASS();
}

TEST(grp_not_enough_captures)
{
  ASSERT_MATCH_G2("(A)(B)(C)", "ABC", 0, 3, 0, 1);
  PASS();
}

TEST(grp_empty_before_some)
{
  ASSERT_MATCH_G2("()A", "A", 0, 1, 0, 0);
  PASS();
}

TEST(grp_too_many_captures)
{
  const char *regex = "(.*)";
  bbre_span check_span[5] = {
      {0, 3},
      {0, 3},
      {0, 0},
      {0, 0},
      {0, 0},
  };
  unsigned int check_did_match[5] = {1, 1, 0, 0, 0};
  PROPAGATE(check_matches_n(
      regex, strlen(regex), "abc", 3, 5, check_span, check_did_match));
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
  RUN_TEST(grp_nested_inlines_resetting);
  RUN_TEST(grp_invalid_unmatched_rparen);
  RUN_TEST(grp_invalid_unmatched_lparen);
  RUN_TEST(grp_nested_in_nonmatching);
  RUN_TEST(grp_too_many_captures);
  RUN_TEST(grp_not_enough_captures);
  RUN_TEST(grp_empty_before_some);
}

TEST(set_init_patterns)
{
  const char *pats[] = {"a", "b*a", "c"};
  unsigned int out_idxs[3] = {0, 0, 0};
  unsigned int num_idxs = 0;
  bbre_set *set = bbre_set_init_patterns(pats, 3);
  if (!set && test_alloc_last_was_null)
    OOM();
  ASSERT_NEQ(set, NULL);
  if (bbre_set_matches(set, "a", 1, out_idxs, 3, &num_idxs) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(num_idxs, 2);
  bbre_set_destroy(set);
  PASS();
oom:
  bbre_set_destroy(set);
  OOM();
}

TEST(set_many)
{
  bbre *patterns[26] = {0};
  bbre_set *set = NULL;
  bbre_set_builder *spec = NULL;
  unsigned int i = 0;
  int err = 0;
  unsigned int pat_ids[2] = {0};
  for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    char pattern[] = {'a', 0};
    pattern[0] += i;
    if (!(patterns[i] = bbre_init_pattern(pattern)))
      goto oom;
    ASSERT_EQ(err, 0);
  }
  if ((err = bbre_set_builder_init(&spec, NULL)) == BBRE_ERR_MEM)
    goto oom;
  for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    if ((err = bbre_set_builder_add(spec, patterns[i])))
      goto oom;
  }
  if ((err = bbre_set_init(&set, spec, NULL)) == BBRE_ERR_MEM)
    goto oom;
  bbre_set_builder_destroy(spec);
  spec = NULL;
  for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    char text[] = {'a', 0};
    unsigned int nmatch = 0;
    text[0] += i;
    if ((err = bbre_set_matches(
             set, text, 1, pat_ids, sizeof(pat_ids) / sizeof(pat_ids[0]),
             &nmatch)) == BBRE_ERR_MEM)
      goto oom;
    ASSERT_EQ(nmatch, 1);
    ASSERT_EQ(err, 1);
    ASSERT_EQ(pat_ids[0], i);
    ASSERT_EQ(pat_ids[1], 0);
    if ((err = bbre_set_matches_at(
             set, text, 1, 0, pat_ids, sizeof(pat_ids) / sizeof(pat_ids[0]),
             &nmatch)) == BBRE_ERR_MEM)
      goto oom;
    ASSERT_EQ(nmatch, 1);
    ASSERT_EQ(err, 1);
    ASSERT_EQ(pat_ids[0], i);
    ASSERT_EQ(pat_ids[1], 0);
  }
  for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    bbre_destroy(patterns[i]);
  bbre_set_destroy(set);
  bbre_set_builder_destroy(spec);
  PASS();
oom:
  for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    bbre_destroy(patterns[i]);
  bbre_set_destroy(set);
  bbre_set_builder_destroy(spec);
  OOM();
}

TEST(set_aliasing)
{
  const char *pats[] = {"a*b", "a*a", "a*ab", "a*aa", "a*aab", "a*aaa"};
  char text[256];
  bbre_set *set = bbre_set_init_patterns(pats, 6);
  int err = 0;
  memset(text, 'a', 256);
  if (!set)
    OOM();
  if ((err = bbre_set_is_match(set, text, sizeof(text)) == BBRE_ERR_MEM))
    goto oom;
  text[sizeof(text) - 1] = 'b';
  if ((err = bbre_set_is_match(set, text, sizeof(text)) == BBRE_ERR_MEM))
    goto oom;
  bbre_set_destroy(set);
  PASS();
oom:
  bbre_set_destroy(set);
  OOM();
}

TEST(set_clone)
{
  const char *pats[] = {"a", "b"};
  int err;
  bbre_set *set = bbre_set_init_patterns(pats, 2), *set2 = NULL;
  if (!set)
    OOM();
  if ((err = bbre_set_clone(&set2, set, NULL)) == BBRE_ERR_MEM)
    goto oom;
  bbre_set_destroy(set2);
  bbre_set_destroy(set);
  PASS();
oom:
  bbre_set_destroy(set2);
  bbre_set_destroy(set);
  OOM();
}

TEST(set_nmatch)
{
  const char *pats[] = {"a$", "b", ".*c"};
  int err;
  bbre_set *set = bbre_set_init_patterns(pats, 3);
  if (!set)
    OOM();
  if ((err = bbre_set_is_match(set, "aaqqq", 5)) < 0)
    goto oom;
  ASSERT_EQ(err, 0);
  bbre_set_destroy(set);
  PASS();
oom:
  bbre_set_destroy(set);
  OOM();
}

TEST(set_is_match_at)
{
  const char *pats[] = {"^q", "r", "s$"};
  int err;
  bbre_set *set = bbre_set_init_patterns(pats, 3);
  if (!set)
    OOM();
  if ((err = bbre_set_is_match_at(set, "qrs", 3, 0)) < 0)
    goto oom;
  ASSERT_EQ(err, 1);
  if ((err = bbre_set_is_match_at(set, "qrs", 3, 1)) < 0)
    goto oom;
  ASSERT_EQ(err, 1);
  if ((err = bbre_set_is_match_at(set, "qrs", 3, 2)) < 0)
    goto oom;
  ASSERT_EQ(err, 1);
  bbre_set_destroy(set);
  PASS();
oom:
  bbre_set_destroy(set);
  OOM();
}

SUITE(set)
{
  RUN_TEST(set_init_patterns);
  RUN_TEST(set_many);
  RUN_TEST(set_aliasing);
  RUN_TEST(set_clone);
  RUN_TEST(set_nmatch);
  RUN_TEST(set_is_match_at);
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
  bbre_builder *spec = NULL;
  bbre *r = NULL;
  int err = 0;
  const char *regex = "a{99999}{2}";
  if ((err = bbre_builder_init(&spec, regex, strlen(regex), NULL)) ==
      BBRE_ERR_MEM)
    goto oom;
  if ((err = bbre_init(&r, spec, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, BBRE_ERR_LIMIT);
  ASSERT(
      !strcmp(bbre_get_err_msg(r), "maximum compiled program size exceeded"));
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  PASS();
oom:
  bbre_destroy(r);
  bbre_builder_destroy(spec);
  OOM();
}

TEST(limit_ast_size)
{
  char *regex = NULL;
  size_t size = 10000000;
  bbre *r = NULL;
  bbre_builder *build = NULL;
  int err = 0;
  regex = MPTEST_MALLOC(size);
  if (!regex)
    goto oom;
  memset(regex, 'a', size);
  if ((err = bbre_builder_init(&build, regex, size, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, 0);
  if ((err = bbre_init(&r, build, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, BBRE_ERR_LIMIT);
  ASSERT_EQ(
      strcmp(bbre_get_err_msg(r), "regular expression is too complex"), 0);
  bbre_destroy(r);
  bbre_builder_destroy(build);
  MPTEST_FREE(regex);
  PASS();
oom:
  bbre_destroy(r);
  bbre_builder_destroy(build);
  MPTEST_FREE(regex);
  OOM();
}

TEST(limit_group_name_size)
{
  char *regex = NULL;
  size_t size = 10000000;
  bbre *r = NULL;
  bbre_builder *build = NULL;
  int err = 0;
  regex = MPTEST_MALLOC(size);
  if (!regex)
    goto oom;
  memset(regex, 'a', size);
  regex[0] = '(', regex[1] = '?', regex[2] = '<';
  regex[size - 2] = '>', regex[size - 1] = ')';
  if ((err = bbre_builder_init(&build, regex, size, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, 0);
  if ((err = bbre_init(&r, build, NULL)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, BBRE_ERR_LIMIT);
  ASSERT_EQ(
      strcmp(bbre_get_err_msg(r), "group name exceeds maximum length"), 0);
  bbre_destroy(r);
  bbre_builder_destroy(build);
  MPTEST_FREE(regex);
  PASS();
oom:
  bbre_destroy(r);
  bbre_builder_destroy(build);
  MPTEST_FREE(regex);
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
  RUN_TEST(limit_ast_size);
  RUN_TEST(limit_group_name_size);
  RUN_TEST(limit_dfa_thrash);
}

TEST(api_is_match_at)
{
  bbre *r = bbre_init_pattern("abc");
  int err;
  if (!r)
    OOM();
  if ((err = bbre_is_match_at(r, "Xabc", 4, 1)) == BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, 1);
  bbre_destroy(r);
  PASS();
oom:
  bbre_destroy(r);
  OOM();
}

TEST(api_version)
{
  bbre *r = bbre_init_pattern("(\\d*)[.](\\d*)[.](\\d*)-?(.*)");
  const char *version_str = bbre_version();
  int err;
  if (!r)
    OOM();
  if ((err = bbre_is_match(r, version_str, strlen(version_str))) ==
      BBRE_ERR_MEM)
    goto oom;
  ASSERT_EQ(err, 1);
  bbre_destroy(r);
  PASS();
oom:
  bbre_destroy(r);
  OOM();
}

SUITE(api)
{
  RUN_TEST(api_is_match_at);
  RUN_TEST(api_version);
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
  RUN_SUITE(api);
  /* regression tests should not account for coverage. we should explicitly
   * write tests that fully cover our code, as they are more documentable than
   * potentially cryptic regression tests. internally, this suite is fused off
   * with an #ifdef BBRE_COV. */
  RUN_SUITE(fuzz_regression);
  return MPTEST_MAIN_END();
}
