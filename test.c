#include <string.h>

/* unfinished: parse string ends early
 * malformed:  parse string contains a malformed utf-8 sequence
 * invalid:    parse string is valid utf-8 but contains an unexpected char */

#define MPTEST_IMPLEMENTATION
#include "mptest/_cpack/mptest.h"

#include "re.h"

#define ASSERT_MATCH(regex, str)                                               \
  do {                                                                         \
    re *r;                                                                     \
    int err;                                                                   \
    if ((err = re_init_full(&r, regex)) == ERR_MEM)                            \
      PASS();                                                                  \
    ASSERT(err != ERR_PARSE);                                                  \
    ASSERT(!err);                                                              \
    ASSERT(re_match(r, str, strlen(str), 0, 0, NULL, NULL, A_BOTH));           \
    re_destroy(r);                                                             \
  } while (0)

#define ASSERT_NMATCH(regex, str)                                              \
  do {                                                                         \
    re *r;                                                                     \
    int err;                                                                   \
    if ((err = re_init_full(&r, regex)) == ERR_MEM)                            \
      PASS();                                                                  \
    ASSERT(err != ERR_PARSE);                                                  \
    ASSERT(!err);                                                              \
    ASSERT(!re_match(r, str, strlen(str), 0, 0, NULL, NULL, A_BOTH));          \
    re_destroy(r);                                                             \
  } while (0)

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

SUITE(cls) {
  RUN_TEST(cls_escape_any_byte);
  RUN_TEST(cls_escape_char_start);
  RUN_TEST(cls_escape_quote);
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

SUITE(escape) {
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
