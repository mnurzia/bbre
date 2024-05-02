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
#define TEST_NAMED_CLASS_RANGE_MAX 128
#endif

size_t utf_encode(char *out_buf, u32 codep) {
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

#define ASSERT_MATCH_N(regex, str, sz)                                         \
  do {                                                                         \
    re *r;                                                                     \
    int err;                                                                   \
    if ((err = re_init_full(&r, regex)) == ERR_MEM)                            \
      PASS();                                                                  \
    ASSERT(err != ERR_PARSE);                                                  \
    ASSERT(!err);                                                              \
    ASSERT(re_match(r, str, sz, 0, 0, NULL, NULL, A_BOTH));                    \
    re_destroy(r);                                                             \
  } while (0)

#define ASSERT_NMATCH_N(regex, str, sz)                                        \
  do {                                                                         \
    re *r;                                                                     \
    int err;                                                                   \
    if ((err = re_init_full(&r, regex)) == ERR_MEM)                            \
      PASS();                                                                  \
    ASSERT(err != ERR_PARSE);                                                  \
    ASSERT(!err);                                                              \
    ASSERT(!re_match(r, str, sz, 0, 0, NULL, NULL, A_BOTH));                   \
    re_destroy(r);                                                             \
  } while (0)

#define ASSERT_MATCH(regex, str) ASSERT_MATCH_N(regex, str, strlen(str))
#define ASSERT_NMATCH(regex, str) ASSERT_NMATCH_N(regex, str, strlen(str))

#define ASSERT_MATCH_1(regex, str, b, e)                                       \
  do {                                                                         \
    re *r;                                                                     \
    int err;                                                                   \
    span s;                                                                    \
    if ((err = re_init_full(&r, regex)) == ERR_MEM)                            \
      PASS();                                                                  \
    ASSERT_NEQ(err, ERR_PARSE);                                                \
    ASSERT(!err);                                                              \
    ASSERT(re_match(r, str, strlen(str), 1, 0, &s, NULL, A_BOTH));             \
    ASSERT_EQ(s.begin, b);                                                     \
    ASSERT_EQ(s.end, e);                                                       \
    re_destroy(r);                                                             \
  } while (0)

#define ASSERT_MATCH_1_A(regex, str, b, e, anchor)                             \
  do {                                                                         \
    re *r;                                                                     \
    int err;                                                                   \
    span s;                                                                    \
    if ((err = re_init_full(&r, regex)) == ERR_MEM)                            \
      PASS();                                                                  \
    ASSERT_NEQ(err, ERR_PARSE);                                                \
    ASSERT(!err);                                                              \
    ASSERT(re_match(r, str, strlen(str), 1, 0, &s, NULL, anchor));             \
    ASSERT_EQ(s.begin, b);                                                     \
    ASSERT_EQ(s.end, e);                                                       \
    re_destroy(r);                                                             \
  } while (0)

#define ASSERT_NOPARSE(regex)                                                  \
  do {                                                                         \
    re *r;                                                                     \
    int err;                                                                   \
    if ((err = re_init_full(&r, regex)) == ERR_MEM)                            \
      PASS();                                                                  \
    ASSERT_EQ(err, ERR_PARSE);                                                 \
  } while (0);

typedef struct rrange {
  u32 lo, hi;
} rrange;

u32 matchnum(const char *num) {
  u32 out = 0;
  unsigned char chout;
  if (sscanf(num, "0x%X", &out))
    return out;
  else if (sscanf(num, "%u", &out))
    return out;
  else if (sscanf(num, "%c", &chout))
    return chout;
  else
    assert(0);
  return 0;
}

u32 matchspec(const char *spec, rrange *ranges) {
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

#define ASSERT_CC_MATCH(regex, spec)                                           \
  do {                                                                         \
    re *r;                                                                     \
    int err;                                                                   \
    u32 codep;                                                                 \
    char utf8[16];                                                             \
    rrange ranges[64];                                                         \
    u32 num_ranges = matchspec(spec, ranges), range_idx;                       \
    if ((err = re_init_full(&r, regex)) == ERR_MEM)                            \
      PASS();                                                                  \
    ASSERT(!err);                                                              \
    for (codep = 0; codep < TEST_NAMED_CLASS_RANGE_MAX; codep++) {             \
      size_t sz = utf_encode(utf8, codep);                                     \
      for (range_idx = 0; range_idx < num_ranges; range_idx++) {               \
        if (codep >= ranges[range_idx].lo && codep <= ranges[range_idx].hi) {  \
          ASSERT(re_match(r, utf8, sz, 0, 0, NULL, NULL, A_BOTH));             \
          break;                                                               \
        }                                                                      \
      }                                                                        \
      if (range_idx == num_ranges)                                             \
        ASSERT(!re_match(r, utf8, sz, 0, 0, NULL, NULL, A_BOTH));              \
    }                                                                          \
    re_destroy(r);                                                             \
  } while (0)

TEST(init) {
  re *r;
  r = re_init("");
  re_destroy(r);
  PASS();
}

TEST(chr_1) {
  ASSERT_MATCH_1("a", "a", 0, 1);
  PASS();
}

SUITE(chr) { RUN_TEST(chr_1); }

TEST(cat) {
  ASSERT_MATCH("ab", "ab");
  ASSERT_MATCH("abc", "abc");
  ASSERT_NMATCH("max", "mxx");
  ASSERT_NMATCH("max", "ma");
  PASS();
}

TEST(quant) {
  ASSERT_MATCH("a*", "");
  ASSERT_MATCH("a*", "a");
  ASSERT_MATCH("a*", "aa");
  ASSERT_MATCH("a*", "aaa");
  ASSERT_NMATCH("a*", "b");
  ASSERT_MATCH("a?", "");
  ASSERT_MATCH("a?", "a");
  ASSERT_NMATCH("a?", "aa");
  ASSERT_NMATCH("a+", "");
  ASSERT_MATCH("a+", "a");
  ASSERT_MATCH("a+", "aa");
  PASS();
}

TEST(alt) {
  ASSERT_MATCH("a|b", "a");
  ASSERT_MATCH("a|b", "b");
  ASSERT_NMATCH("a|b", "c");
  ASSERT_MATCH("aaa|b", "aaa");
  PASS();
}

TEST(cls) {
  ASSERT_MATCH("[a]", "a");
  ASSERT_MATCH("[aa]", "a");
  ASSERT_MATCH("[a-mo-q]", "a");
  ASSERT_MATCH("[]]", "]");
  PASS();
}

TEST(bounds) {
  ASSERT_MATCH_1("", "", 0, 0);
  ASSERT_MATCH_1("a", "a", 0, 1);
  ASSERT_MATCH_1("a|b", "a", 0, 1);
  ASSERT_MATCH_1("aa", "aa", 0, 2);
  PASS();
}

TEST(unanchored) {
  ASSERT_MATCH_1_A("a", "ba", 1, 2, A_UNANCHORED);
  PASS();
}

TEST(unicode_1) {
  ASSERT_MATCH_1("a", "a", 0, 1);
  PASS();
}

TEST(unicode_2) {
  ASSERT_MATCH_1("\xd4\x80", "\xd4\x80", 0, 2);
  PASS();
}

TEST(unicode_3) {
  ASSERT_MATCH_1("\xe2\x98\x85", "\xe2\x98\x85", 0, 3);
  PASS();
}

TEST(unicode_4) {
  ASSERT_MATCH_1("\xf0\x9f\xa4\xa0", "\xf0\x9f\xa4\xa0", 0, 4);
  PASS();
}

TEST(unicode_malformed) {
  ASSERT_NOPARSE("\xff");
  PASS();
}

SUITE(unicode) {
  RUN_TEST(unicode_1);
  RUN_TEST(unicode_2);
  RUN_TEST(unicode_3);
  RUN_TEST(unicode_4);
  RUN_TEST(unicode_malformed);
}

TEST(anychar_unicode_1) {
  ASSERT_MATCH(".", "z");
  PASS();
}

TEST(anychar_unicode_2) {
  ASSERT_MATCH(".", "\xce\x88");
  PASS();
}

TEST(anychar_unicode_3) {
  ASSERT_MATCH(".", "\xe0\xa4\x82");
  PASS();
}

TEST(anychar_unicode_4) {
  ASSERT_MATCH(".", "\xf2\x92\x8d\xb2");
  PASS();
}

TEST(anychar_unicode_malformed) {
  ASSERT_NMATCH(".", "\xff");
  PASS();
}

SUITE(anychar) {
  RUN_TEST(anychar_unicode_1);
  RUN_TEST(anychar_unicode_2);
  RUN_TEST(anychar_unicode_3);
  RUN_TEST(anychar_unicode_4);
  RUN_TEST(anychar_unicode_malformed);
}

TEST(any_byte_ascii) {
  ASSERT_MATCH("\\C", "a");
  PASS();
}

TEST(any_byte_nonascii) {
  ASSERT_MATCH("\\C", "\xff");
  PASS();
}

TEST(any_byte) {
  char text[2] = {0};
  text[0] = RAND_PARAM(256);
  ASSERT_MATCH("\\C", text);
  PASS();
}

SUITE(any_byte) {
  RUN_TEST(any_byte_ascii);
  RUN_TEST(any_byte_nonascii);
  FUZZ_TEST(any_byte);
}

TEST(cls_escape_any_byte) {
  ASSERT_NOPARSE("[\\C]");
  PASS();
}

TEST(cls_escape_char_start) {
  ASSERT_MATCH("[\a]", "\a");
  PASS();
}

TEST(cls_escape_quote) {
  ASSERT_NOPARSE("[\\Qabc\\E]");
  PASS();
}

SUITE(cls_escape) {
  RUN_TEST(cls_escape_any_byte);
  RUN_TEST(cls_escape_char_start);
  RUN_TEST(cls_escape_quote);
}

TEST(cls_empty) {
  ASSERT_NOPARSE("[]");
  PASS();
}

TEST(cls_ending_right_bracket) {
  ASSERT_CC_MATCH("[]]", "]");
  PASS();
}

TEST(cls_single) {
  ASSERT_CC_MATCH("[a]", "a");
  PASS();
}

TEST(cls_range_one) {
  ASSERT_CC_MATCH("[a-z]", "a z");
  PASS();
}

TEST(cls_range_one_inverted) {
  ASSERT_CC_MATCH("[^a-z]", "0 `,{ 0x10FFFF");
  PASS();
}

TEST(cls_ending_dash) {
  ASSERT_CC_MATCH("[-]", "-");
  PASS();
}

SUITE(cls) {
  RUN_SUITE(cls_escape);
  RUN_TEST(cls_empty);
  RUN_TEST(cls_ending_right_bracket);
  RUN_TEST(cls_single);
  RUN_TEST(cls_range_one);
  RUN_TEST(cls_range_one_inverted);
  RUN_TEST(cls_ending_dash);
}

TEST(escape_null) {
  ASSERT_MATCH_N("\\0", "\x00", 1);
  PASS();
}

TEST(escape_bell) {
  ASSERT_MATCH_1("\\a", "\x07", 0, 1);
  PASS();
}

TEST(escape_formfeed) {
  ASSERT_MATCH_1("\\f", "\x0C", 0, 1);
  PASS();
}

TEST(escape_tab) {
  ASSERT_MATCH_1("\\t", "\x09", 0, 1);
  PASS();
}

TEST(escape_newline) {
  ASSERT_MATCH_1("\\n", "\x0A", 0, 1);
  PASS();
}

TEST(escape_return) {
  ASSERT_MATCH_1("\\r", "\x0D", 0, 1);
  PASS();
}

TEST(escape_vtab) {
  ASSERT_MATCH_1("\\v", "\v", 0, 1);
  PASS();
}

TEST(escape_question) {
  ASSERT_MATCH_1("\\?", "?", 0, 1);
  PASS();
}

TEST(escape_asterisk) {
  ASSERT_MATCH_1("\\*", "*", 0, 1);
  PASS();
}

TEST(escape_plus) {
  ASSERT_MATCH_1("\\+", "+", 0, 1);
  PASS();
}

TEST(escape_open_parenthesis) {
  ASSERT_MATCH_1("\\(", "(", 0, 1);
  PASS();
}

TEST(escape_close_parenthesis) {
  ASSERT_MATCH_1("\\)", ")", 0, 1);
  PASS();
}

TEST(escape_pipe) {
  ASSERT_MATCH_1("\\|", "|", 0, 1);
  PASS();
}

TEST(escape_octal_1) {
  ASSERT_MATCH_1("\\1", "\001", 0, 1);
  PASS();
}

TEST(escape_octal_2) {
  ASSERT_MATCH_1("\\73", "\073", 0, 1);
  PASS();
}

TEST(escape_octal_3) {
  ASSERT_MATCH_1("\\123", "\123", 0, 1);
  PASS();
}

TEST(escape_octal_nonascii) {
  ASSERT_MATCH_1("\\777", "\xc7\xbf", 0, 2);
  PASS();
}

TEST(escape_octal_malformed) {
  ASSERT_NOPARSE("\\1\xff");
  PASS();
}

TEST(escape_octal_truncated) {
  /* octal escapes less than three characters should be truncated by a non-octal
   * character */
  ASSERT_MATCH_1("\\7a", "\007a", 0, 2);
  PASS();
}

SUITE(escape_octal) {
  RUN_TEST(escape_octal_1);
  RUN_TEST(escape_octal_2);
  RUN_TEST(escape_octal_3);
  RUN_TEST(escape_octal_nonascii);
  RUN_TEST(escape_octal_malformed);
  RUN_TEST(escape_octal_truncated);
}

TEST(escape_hex) {
  ASSERT_MATCH_1("\\x20", "\x20", 0, 1);
  PASS();
}

TEST(escape_hex_unfinished) {
  ASSERT_NOPARSE("\\x");
  PASS();
}

TEST(escape_hex_unfinished_1) {
  ASSERT_NOPARSE("\\x1");
  PASS();
}

TEST(escape_hex_malformed) {
  ASSERT_NOPARSE("\\x\xff");
  PASS();
}

TEST(escape_hex_malformed_1) {
  ASSERT_NOPARSE("\\x1\xff");
  PASS();
}

TEST(escape_hex_invalid) {
  ASSERT_NOPARSE("\\xx");
  PASS();
}

TEST(escape_hex_invalid_1) {
  ASSERT_NOPARSE("\\x1x");
  PASS();
}

SUITE(escape_hex) {
  RUN_TEST(escape_hex);
  RUN_TEST(escape_hex_unfinished);
  RUN_TEST(escape_hex_unfinished_1);
  RUN_TEST(escape_hex_malformed);
  RUN_TEST(escape_hex_malformed_1);
  RUN_TEST(escape_hex_invalid);
  RUN_TEST(escape_hex_invalid_1);
}

TEST(escape_hex_long_1) {
  ASSERT_MATCH("\\x{1}", "\x01");
  PASS();
}

TEST(escape_hex_long_2) {
  ASSERT_MATCH("\\x{20}", " ");
  PASS();
}

TEST(escape_hex_long_3) {
  ASSERT_MATCH("\\x{7FF}", "\xdf\xbf");
  PASS();
}

TEST(escape_hex_long_4) {
  ASSERT_MATCH("\\x{4096}", "\xe4\x82\x96");
  PASS();
}

TEST(escape_hex_long_5) {
  ASSERT_MATCH("\\x{15392}", "\xf0\x95\x8e\x92");
  PASS();
}

TEST(escape_hex_long_6) {
  ASSERT_MATCH("\\x{10FF01}", "\xf4\x8f\xbc\x81");
  PASS();
}

TEST(escape_hex_long_unfinished) {
  ASSERT_NOPARSE("\\x{");
  PASS();
}

TEST(escape_hex_long_unfinished_aftersome) {
  ASSERT_NOPARSE("\\x{1");
  PASS();
}

TEST(escape_hex_long_too_long) {
  /* bracketed hex literals should only be up to six characters */
  ASSERT_NOPARSE("\\x{1000000}");
  PASS();
}

TEST(escape_hex_long_out_of_range) {
  /* bracketed hex literals should not be greater than 0x10FFFF */
  ASSERT_NOPARSE("\\x{110000}");
  PASS();
}

SUITE(escape_hex_long) {
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

TEST(escape_any_byte) {
  ASSERT_MATCH("\\C", "\x11");
  PASS();
}

TEST(escape_quote_empty) {
  ASSERT_MATCH("\\Q\\E", "");
  PASS();
}

TEST(escape_quote_text) {
  ASSERT_MATCH("\\Qabc\\E", "abc");
  PASS();
}

TEST(escape_quote_unfinished) {
  ASSERT_MATCH("\\Qabc", "abc");
  PASS();
}

TEST(escape_quote_unfinished_empty) {
  ASSERT_MATCH("abc\\Q", "abc");
  PASS();
}

TEST(escape_quote_single_slash_unfinished) {
  /* a *single* slash at the end of a string within a quoted escape is just a
   * slash */
  ASSERT_MATCH("\\Q\\", "\\");
  PASS();
}

TEST(escape_quote_double_slash) {
  /* a double slash is escaped as a single slash */
  ASSERT_MATCH("\\Q\\\\\\E", "\\");
  PASS();
}

TEST(escape_quote_single_slash_with_non_E) {
  /* a slash followed by some non-E character is a single slash followed by that
   * character */
  ASSERT_MATCH("\\Q\\AE", "\\A");
  PASS();
}

SUITE(escape_quote) {
  RUN_TEST(escape_quote_empty);
  RUN_TEST(escape_quote_text);
  RUN_TEST(escape_quote_unfinished);
  RUN_TEST(escape_quote_unfinished_empty);
  RUN_TEST(escape_quote_single_slash_unfinished);
  RUN_TEST(escape_quote_double_slash);
  RUN_TEST(escape_quote_single_slash_with_non_E);
}

TEST(named_charclass_alnum) {
  ASSERT_CC_MATCH("[:alnum:]", "0x30 0x39,0x41 0x5A,0x61 0x7A");
  PASS();
}

TEST(named_charclass_alpha) {
  ASSERT_CC_MATCH("[:alpha:]", "0x41 0x5A,0x61 0x7A");
  PASS();
}

TEST(named_charclass_ascii) {
  ASSERT_CC_MATCH("[:ascii:]", "0x0 0x7F");
  PASS();
}

TEST(named_charclass_blank) {
  ASSERT_CC_MATCH("[:blank:]", "0x9 0x9,0x20 0x20");
  PASS();
}

TEST(named_charclass_cntrl) {
  ASSERT_CC_MATCH("[:cntrl:]", "0x0 0x1F,0x7F 0x7F");
  PASS();
}

TEST(named_charclass_digit) {
  ASSERT_CC_MATCH("[:digit:]", "0x30 0x39");
  PASS();
}

TEST(named_charclass_graph) {
  ASSERT_CC_MATCH("[:graph:]", "0x21 0x7E");
  PASS();
}

TEST(named_charclass_lower) {
  ASSERT_CC_MATCH("[:lower:]", "0x61 0x7A");
  PASS();
}

TEST(named_charclass_print) {
  ASSERT_CC_MATCH("[:print:]", "0x20 0x7E");
  PASS();
}

TEST(named_charclass_punct) {
  ASSERT_CC_MATCH("[:punct:]", "0x21 0x2F,0x3A 0x40,0x5B 0x60,0x7B 0x7E");
  PASS();
}

TEST(named_charclass_space) {
  ASSERT_CC_MATCH("[:space:]", "0x9 0xD,0x20 0x20");
  PASS();
}

TEST(named_charclass_perl_space) {
  ASSERT_CC_MATCH("[:perl_space:]", "0x9 0xA,0xC 0xD,0x20 0x20");
  PASS();
}

TEST(named_charclass_upper) {
  ASSERT_CC_MATCH("[:upper:]", "0x41 0x5A");
  PASS();
}

TEST(named_charclass_word) {
  ASSERT_CC_MATCH("[:word:]", "0x30 0x39,0x41 0x5A,0x61 0x7A");
  PASS();
}

TEST(named_charclass_xdigit) {
  ASSERT_CC_MATCH("[:xdigit:]", "0x30 0x39,0x41 0x46,0x61 0x66");
  PASS();
}

SUITE(named_charclass) {
  RUN_TEST(named_charclass_alnum);
  RUN_TEST(named_charclass_alpha);
  RUN_TEST(named_charclass_ascii);
  RUN_TEST(named_charclass_blank);
  RUN_TEST(named_charclass_cntrl);
  RUN_TEST(named_charclass_digit);
  RUN_TEST(named_charclass_graph);
  RUN_TEST(named_charclass_lower);
  RUN_TEST(named_charclass_print);
  RUN_TEST(named_charclass_punct);
  RUN_TEST(named_charclass_space);
  RUN_TEST(named_charclass_perl_space);
  RUN_TEST(named_charclass_upper);
  RUN_TEST(named_charclass_word);
  RUN_TEST(named_charclass_xdigit);
}

TEST(escape_perlclass_D) {
  ASSERT_CC_MATCH("\\D", "0x0 0x2F,0x3A 0x10FFFF");
  PASS();
}

TEST(escape_perlclass_d) {
  ASSERT_CC_MATCH("\\d", "0x30 0x39");
  PASS();
}

TEST(escape_perlclass_S) {
  ASSERT_CC_MATCH("\\S", "0x0 0x8,0xB 0xB,0xE 0x1F,0x21 0x10FFFF");
  PASS();
}

TEST(escape_perlclass_s) {
  ASSERT_CC_MATCH("\\s", "0x9 0xA,0xC 0xD,0x20 0x20");
  PASS();
}

TEST(escape_perlclass_W) {
  ASSERT_CC_MATCH("\\W", "0x0 0x2F,0x3A 0x40,0x5B 0x60,0x7B 0x10FFFF");
  PASS();
}

TEST(escape_perlclass_w) {
  ASSERT_CC_MATCH("\\w", "0x30 0x39,0x41 0x5A,0x61 0x7A");
  PASS();
}

SUITE(escape_perlclass) {
  RUN_TEST(escape_perlclass_D);
  RUN_TEST(escape_perlclass_d);
  RUN_TEST(escape_perlclass_S);
  RUN_TEST(escape_perlclass_s);
  RUN_TEST(escape_perlclass_W);
  RUN_TEST(escape_perlclass_w);
}

SUITE(escape) {
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
  RUN_TEST(escape_pipe);
  RUN_SUITE(escape_octal);
  RUN_SUITE(escape_hex);
  RUN_SUITE(escape_hex_long);
  RUN_TEST(escape_any_byte);
  RUN_SUITE(escape_quote);
  RUN_SUITE(escape_perlclass);
}

int main(int argc, const char *const *argv) {
  MPTEST_MAIN_BEGIN_ARGS(argc, argv);
  RUN_TEST(init);
  RUN_SUITE(chr);
  RUN_TEST(cat);
  RUN_TEST(quant);
  RUN_TEST(alt);
  RUN_TEST(cls);
  RUN_TEST(bounds);
  RUN_TEST(unanchored);
  RUN_SUITE(unicode);
  RUN_SUITE(any_byte);
  RUN_SUITE(cls);
  RUN_SUITE(anychar);
  RUN_SUITE(escape);
  MPTEST_MAIN_END();
}
