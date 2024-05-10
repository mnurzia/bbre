#include <string.h>

/* unfinished: parse string ends early
 * malformed:  parse string contains a malformed utf-8 sequence
 * invalid:    parse string is valid utf-8 but contains an unexpected char */

#define MPTEST_IMPLEMENTATION
#include "mptest/_cpack/mptest.h"

#include "re.h"

#ifdef TEST_BULK
  #define TEST_NAMED_CLASS_RANGE_MAX 0x110000
#else
  #define TEST_NAMED_CLASS_RANGE_MAX 0x80
#endif

void *test_alloc(size_t prev, size_t next, void *ptr)
{
  if (!prev && next) {
    return MPTEST_INJECT_MALLOC(next);
  } else if (next) {
    assert(prev || !ptr);
    return MPTEST_INJECT_REALLOC(ptr, next);
  } else if (ptr) {
    MPTEST_INJECT_FREE(ptr);
  }
  return NULL;
}

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

#define IMPLIES(c, pred) (!(c) || (pred))

int check_match(
    const char *regex, const char *s, size_t n, u32 max_span, u32 max_set,
    anchor_type anchor, span *check_span, u32 *check_set, u32 check_nsets)
{
  re *r;
  int err;
  span *found_span;
  u32 *found_set, i, j;
  found_span = test_alloc(0, sizeof(span) * max_span * max_set, NULL);
  if (max_span * max_set && !found_span)
    OOM();
  found_set = test_alloc(0, sizeof(u32) * max_set, NULL);
  if (max_set && !found_set)
    OOM();
  if ((err = re_init_full(&r, regex, test_alloc)) == ERR_MEM)
    OOM();
  ASSERT_EQ(err, 0);
  if ((err = re_match(
           r, s, n, max_span, max_set, found_span, found_set, anchor)) ==
      ERR_MEM)
    OOM();
  ASSERT_EQ((u32)err, check_nsets);
  for (i = 0; i < (check_nsets > max_set ? max_set : check_nsets); i++) {
    if (check_set)
      ASSERT_EQ(check_set[i], found_set[i]);
    for (j = 0; j < max_span; j++) {
      ASSERT_EQ(
          check_span[i * max_span + j].begin,
          found_span[i * max_span + j].begin);
      ASSERT_EQ(
          check_span[i * max_span + j].end, found_span[i * max_span + j].end);
    }
  }
  re_destroy(r);
  test_alloc(sizeof(span) * max_span * max_set, 0, found_span);
  test_alloc(sizeof(u32) * max_set, 0, found_set);
  PASS();
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

#define ASSERT_MATCH(regex, str)  PROPAGATE(check_fullmatch(regex, str))
#define ASSERT_NMATCH(regex, str) PROPAGATE(check_not_fullmatch(regex, str))
#define ASSERT_MATCH_N(regex, str, sz)                                         \
  PROPAGATE(check_fullmatch_n(regex, str, sz));
#define ASSERT_NMATCH_N(regex, str, sz)                                        \
  PROPAGATE(check_not_fullmatch_n(regex, str, sz));
#define ASSERT_MATCH_1_A(regex, str, b, e, anchor)                             \
  PROPAGATE(check_match_g1_a(regex, str, b, e, anchor))
#define ASSERT_MATCH_1(regex, str, b, e)                                       \
  ASSERT_MATCH_1_A(regex, str, b, e, A_BOTH)

#define ASSERT_MATCH_ONLY(regex, str) ASSERT_MATCH(regex, str)

int check_noparse(const char *regex)
{
  re *r;
  int err;
  if ((err = re_init_full(&r, regex, test_alloc)) == ERR_MEM)
    OOM();
  ASSERT_EQ(err, ERR_PARSE);
  re_destroy(r);
  PASS();
}

#define ASSERT_NOPARSE(regex) PROPAGATE(check_noparse(regex))

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
    const char *comma = strchr(spec, ','), *nextspec = comma + 1;
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

int assert_cc_match(const char *regex, const char *spec)
{
  re *r;
  int err;
  u32 codep;
  char utf8[16];
  rrange ranges[64];
  u32 num_ranges = matchspec(spec, ranges), range_idx;
  if ((err = re_init_full(&r, regex, test_alloc)) == ERR_MEM)
    OOM();
  ASSERT(!err);
  for (codep = 0; codep < TEST_NAMED_CLASS_RANGE_MAX; codep++) {
    size_t sz = utf_encode(utf8, codep);
    for (range_idx = 0; range_idx < num_ranges; range_idx++) {
      if (codep >= ranges[range_idx].lo && codep <= ranges[range_idx].hi) {
        if ((err = re_match(r, utf8, sz, 0, 0, NULL, NULL, A_BOTH)) == ERR_MEM)
          OOM();
        ASSERT_EQ(err, 1);
        break;
      }
    }
    if (range_idx == num_ranges) {
      if ((err = re_match(r, utf8, sz, 0, 0, NULL, NULL, A_BOTH)) == ERR_MEM)
        OOM();
      ASSERT_EQ(err, 0);
    }
  }
  re_destroy(r);
  PASS();
}

#define ASSERT_CC_MATCH(regex, spec) PROPAGATE(assert_cc_match(regex, spec))

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

TEST(init_bad)
{
  /* TODO: explicitly detect the parse error */
  re *r = re_init("\xff");
  if (!r)
    OOM();
  re_destroy(r);
  PASS();
}

SUITE(init)
{
  RUN_TEST(init_empty);
  RUN_TEST(init_some);
  RUN_TEST(init_bad);
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

SUITE(star)
{
  RUN_TEST(star_empty);
  RUN_TEST(star_one);
  RUN_TEST(star_two);
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

SUITE(quant)
{
  RUN_SUITE(star);
  RUN_SUITE(quest);
  RUN_SUITE(plus);
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
}

TEST(cls)
{
  ASSERT_MATCH("[a]", "a");
  ASSERT_MATCH("[aa]", "a");
  ASSERT_MATCH("[a-mo-q]", "a");
  ASSERT_MATCH("[]]", "]");
  PASS();
}

TEST(bounds)
{
  ASSERT_MATCH_1("", "", 0, 0);
  ASSERT_MATCH_1("a", "a", 0, 1);
  ASSERT_MATCH_1("a|b", "a", 0, 1);
  ASSERT_MATCH_1("aa", "aa", 0, 2);
  PASS();
}

TEST(unanchored)
{
  ASSERT_MATCH_1_A("a", "ba", 1, 2, A_UNANCHORED);
  PASS();
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

TEST(cls_single)
{
  ASSERT_CC_MATCH("[a]", "a");
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

TEST(cls_named_unknown)
{
  ASSERT_NOPARSE("[[:unknown:]]");
  PASS();
}

SUITE(cls)
{
  RUN_SUITE(cls_escape);
  RUN_TEST(cls_empty);
  RUN_TEST(cls_ending_right_bracket);
  RUN_TEST(cls_single);
  RUN_TEST(cls_range_one);
  RUN_TEST(cls_range_one_inverted);
  RUN_TEST(cls_ending_dash);
  RUN_TEST(cls_named_unfinished);
  RUN_TEST(cls_named_unknown);
}

TEST(escape_null)
{
  ASSERT_MATCH_N("\\0", "\x00", 1);
  PASS();
}

TEST(escape_bell)
{
  ASSERT_MATCH_1("\\a", "\x07", 0, 1);
  PASS();
}

TEST(escape_formfeed)
{
  ASSERT_MATCH_1("\\f", "\x0C", 0, 1);
  PASS();
}

TEST(escape_tab)
{
  ASSERT_MATCH_1("\\t", "\x09", 0, 1);
  PASS();
}

TEST(escape_newline)
{
  ASSERT_MATCH_1("\\n", "\x0A", 0, 1);
  PASS();
}

TEST(escape_return)
{
  ASSERT_MATCH_1("\\r", "\x0D", 0, 1);
  PASS();
}

TEST(escape_vtab)
{
  ASSERT_MATCH_1("\\v", "\v", 0, 1);
  PASS();
}

TEST(escape_question)
{
  ASSERT_MATCH_1("\\?", "?", 0, 1);
  PASS();
}

TEST(escape_asterisk)
{
  ASSERT_MATCH_1("\\*", "*", 0, 1);
  PASS();
}

TEST(escape_plus)
{
  ASSERT_MATCH_1("\\+", "+", 0, 1);
  PASS();
}

TEST(escape_open_parenthesis)
{
  ASSERT_MATCH_1("\\(", "(", 0, 1);
  PASS();
}

TEST(escape_close_parenthesis)
{
  ASSERT_MATCH_1("\\)", ")", 0, 1);
  PASS();
}

TEST(escape_open_bracket)
{
  ASSERT_MATCH_1("\\[", "[", 0, 1);
  PASS();
}

TEST(escape_close_bracket)
{
  ASSERT_MATCH_1("\\]", "]", 0, 1);
  PASS();
}

TEST(escape_open_curly_bracket)
{
  ASSERT_MATCH_1("\\{", "{", 0, 1);
  PASS();
}

TEST(escape_close_curly_bracket)
{
  ASSERT_MATCH_1("\\}", "}", 0, 1);
  PASS();
}

TEST(escape_pipe)
{
  ASSERT_MATCH_1("\\|", "|", 0, 1);
  PASS();
}

TEST(escape_slash)
{
  ASSERT_MATCH_1("\\\\", "\\", 0, 1);
  PASS();
}

TEST(escape_octal_1)
{
  ASSERT_MATCH_1("\\1", "\001", 0, 1);
  PASS();
}

TEST(escape_octal_2)
{
  ASSERT_MATCH_1("\\73", "\073", 0, 1);
  PASS();
}

TEST(escape_octal_3)
{
  ASSERT_MATCH_1("\\123", "\123", 0, 1);
  PASS();
}

TEST(escape_octal_nonascii)
{
  ASSERT_MATCH_1("\\777", "\xc7\xbf", 0, 2);
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
  ASSERT_MATCH_1("\\7a", "\007a", 0, 2);
  PASS();
}

TEST(escape_octal_truncated_2)
{
  /* octal escapes less than three characters should be truncated by a non-octal
   * character */
  ASSERT_MATCH_1("\\30a", "\030a", 0, 2);
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
  ASSERT_MATCH_1("\\x20", "\x20", 0, 1);
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

SUITE(escape_hex)
{
  RUN_TEST(escape_hex);
  RUN_TEST(escape_hex_unfinished);
  RUN_TEST(escape_hex_unfinished_1);
  RUN_TEST(escape_hex_malformed);
  RUN_TEST(escape_hex_malformed_1);
  RUN_TEST(escape_hex_invalid);
  RUN_TEST(escape_hex_invalid_1);
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

SUITE(escape_quote)
{
  RUN_TEST(escape_quote_empty);
  RUN_TEST(escape_quote_text);
  RUN_TEST(escape_quote_unfinished);
  RUN_TEST(escape_quote_unfinished_empty);
  RUN_TEST(escape_quote_single_slash_unfinished);
  RUN_TEST(escape_quote_double_slash);
  RUN_TEST(escape_quote_single_slash_with_non_E);
}

SUITE(escape_perlclass); /* provided by test-gen.c */

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
  RUN_SUITE(escape_octal);
  RUN_SUITE(escape_hex);
  RUN_SUITE(escape_hex_long);
  RUN_TEST(escape_any_byte);
  RUN_SUITE(escape_quote);
  RUN_SUITE(escape_perlclass);
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
}

TEST(grp_flags)
{
  ASSERT_MATCH("(?i:a)", "A");
  PASS();
}

SUITE(grp) { RUN_TEST(grp_flags); }

int main(int argc, const char *const *argv)
{
  MPTEST_MAIN_BEGIN_ARGS(argc, argv);
  RUN_SUITE(init);
  RUN_SUITE(chr);
  RUN_SUITE(cat);
  RUN_SUITE(quant);
  RUN_SUITE(alt);
  RUN_TEST(cls);
  RUN_TEST(bounds);
  RUN_TEST(unanchored);
  RUN_SUITE(any_byte);
  RUN_SUITE(cls);
  RUN_SUITE(anychar);
  RUN_SUITE(escape);
  RUN_SUITE(repetition);
  RUN_SUITE(grp);
  MPTEST_MAIN_END();
}
