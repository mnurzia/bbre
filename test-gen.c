#include "mptest/_cpack/mptest.h"
#include "re.h"

mptest__result assert_cc_match(const char *regex, const char *spec, int invert);
int check_noparse_n(const char *regex, size_t n);
int check_compiles_n(const char *regex, size_t n);
int check_matches_n(
    const char **regexes, size_t *regex_n, u32 nregex, const char *s, size_t n,
    u32 max_span, u32 max_set, anchor_type anchor, span *check_span,
    u32 *check_set, u32 check_nsets);

/*T Generated by `unicode_data.py gen_ascii_charclasses test` */

TEST(cls_named_alnum)
{
  PROPAGATE(assert_cc_match("[[:alnum:]]", "0x30 0x39,0x41 0x5A,0x61 0x7A", 0));
  PASS();
}

TEST(cls_named_alnum_invert)
{
  PROPAGATE(
      assert_cc_match("[[:^alnum:]]", "0x30 0x39,0x41 0x5A,0x61 0x7A", 1));
  PASS();
}

TEST(cls_named_alpha)
{
  PROPAGATE(assert_cc_match("[[:alpha:]]", "0x41 0x5A,0x61 0x7A", 0));
  PASS();
}

TEST(cls_named_alpha_invert)
{
  PROPAGATE(assert_cc_match("[[:^alpha:]]", "0x41 0x5A,0x61 0x7A", 1));
  PASS();
}

TEST(cls_named_ascii)
{
  PROPAGATE(assert_cc_match("[[:ascii:]]", "0x0 0x7F", 0));
  PASS();
}

TEST(cls_named_ascii_invert)
{
  PROPAGATE(assert_cc_match("[[:^ascii:]]", "0x0 0x7F", 1));
  PASS();
}

TEST(cls_named_blank)
{
  PROPAGATE(assert_cc_match("[[:blank:]]", "0x9 0x9,0x20 0x20", 0));
  PASS();
}

TEST(cls_named_blank_invert)
{
  PROPAGATE(assert_cc_match("[[:^blank:]]", "0x9 0x9,0x20 0x20", 1));
  PASS();
}

TEST(cls_named_cntrl)
{
  PROPAGATE(assert_cc_match("[[:cntrl:]]", "0x0 0x1F,0x7F 0x7F", 0));
  PASS();
}

TEST(cls_named_cntrl_invert)
{
  PROPAGATE(assert_cc_match("[[:^cntrl:]]", "0x0 0x1F,0x7F 0x7F", 1));
  PASS();
}

TEST(cls_named_digit)
{
  PROPAGATE(assert_cc_match("[[:digit:]]", "0x30 0x30,0x39 0x39", 0));
  PASS();
}

TEST(cls_named_digit_invert)
{
  PROPAGATE(assert_cc_match("[[:^digit:]]", "0x30 0x30,0x39 0x39", 1));
  PASS();
}

TEST(cls_named_graph)
{
  PROPAGATE(assert_cc_match("[[:graph:]]", "0x21 0x21,0x7E 0x7E", 0));
  PASS();
}

TEST(cls_named_graph_invert)
{
  PROPAGATE(assert_cc_match("[[:^graph:]]", "0x21 0x21,0x7E 0x7E", 1));
  PASS();
}

TEST(cls_named_lower)
{
  PROPAGATE(assert_cc_match("[[:lower:]]", "0x61 0x61,0x7A 0x7A", 0));
  PASS();
}

TEST(cls_named_lower_invert)
{
  PROPAGATE(assert_cc_match("[[:^lower:]]", "0x61 0x61,0x7A 0x7A", 1));
  PASS();
}

TEST(cls_named_print)
{
  PROPAGATE(assert_cc_match("[[:print:]]", "0x20 0x7E", 0));
  PASS();
}

TEST(cls_named_print_invert)
{
  PROPAGATE(assert_cc_match("[[:^print:]]", "0x20 0x7E", 1));
  PASS();
}

TEST(cls_named_punct)
{
  PROPAGATE(assert_cc_match(
      "[[:punct:]]", "0x21 0x2F,0x3A 0x40,0x5B 0x60,0x7B 0x7E", 0));
  PASS();
}

TEST(cls_named_punct_invert)
{
  PROPAGATE(assert_cc_match(
      "[[:^punct:]]", "0x21 0x2F,0x3A 0x40,0x5B 0x60,0x7B 0x7E", 1));
  PASS();
}

TEST(cls_named_space)
{
  PROPAGATE(assert_cc_match("[[:space:]]", "0x9 0xD,0x20 0x20", 0));
  PASS();
}

TEST(cls_named_space_invert)
{
  PROPAGATE(assert_cc_match("[[:^space:]]", "0x9 0xD,0x20 0x20", 1));
  PASS();
}

TEST(cls_named_perl_space)
{
  PROPAGATE(
      assert_cc_match("[[:perl_space:]]", "0x9 0xA,0xC 0xD,0x20 0x20", 0));
  PASS();
}

TEST(cls_named_perl_space_invert)
{
  PROPAGATE(
      assert_cc_match("[[:^perl_space:]]", "0x9 0xA,0xC 0xD,0x20 0x20", 1));
  PASS();
}

TEST(cls_named_upper)
{
  PROPAGATE(assert_cc_match("[[:upper:]]", "0x41 0x41,0x5A 0x5A", 0));
  PASS();
}

TEST(cls_named_upper_invert)
{
  PROPAGATE(assert_cc_match("[[:^upper:]]", "0x41 0x41,0x5A 0x5A", 1));
  PASS();
}

TEST(cls_named_word)
{
  PROPAGATE(assert_cc_match("[[:word:]]", "0x30 0x39,0x41 0x5A,0x61 0x7A", 0));
  PASS();
}

TEST(cls_named_word_invert)
{
  PROPAGATE(assert_cc_match("[[:^word:]]", "0x30 0x39,0x41 0x5A,0x61 0x7A", 1));
  PASS();
}

TEST(cls_named_xdigit)
{
  PROPAGATE(
      assert_cc_match("[[:xdigit:]]", "0x30 0x39,0x41 0x46,0x61 0x66", 0));
  PASS();
}

TEST(cls_named_xdigit_invert)
{
  PROPAGATE(
      assert_cc_match("[[:^xdigit:]]", "0x30 0x39,0x41 0x46,0x61 0x66", 1));
  PASS();
}

SUITE(cls_named)
{
  RUN_TEST(cls_named_alnum);
  RUN_TEST(cls_named_alnum_invert);
  RUN_TEST(cls_named_alpha);
  RUN_TEST(cls_named_alpha_invert);
  RUN_TEST(cls_named_ascii);
  RUN_TEST(cls_named_ascii_invert);
  RUN_TEST(cls_named_blank);
  RUN_TEST(cls_named_blank_invert);
  RUN_TEST(cls_named_cntrl);
  RUN_TEST(cls_named_cntrl_invert);
  RUN_TEST(cls_named_digit);
  RUN_TEST(cls_named_digit_invert);
  RUN_TEST(cls_named_graph);
  RUN_TEST(cls_named_graph_invert);
  RUN_TEST(cls_named_lower);
  RUN_TEST(cls_named_lower_invert);
  RUN_TEST(cls_named_print);
  RUN_TEST(cls_named_print_invert);
  RUN_TEST(cls_named_punct);
  RUN_TEST(cls_named_punct_invert);
  RUN_TEST(cls_named_space);
  RUN_TEST(cls_named_space_invert);
  RUN_TEST(cls_named_perl_space);
  RUN_TEST(cls_named_perl_space_invert);
  RUN_TEST(cls_named_upper);
  RUN_TEST(cls_named_upper_invert);
  RUN_TEST(cls_named_word);
  RUN_TEST(cls_named_word_invert);
  RUN_TEST(cls_named_xdigit);
  RUN_TEST(cls_named_xdigit_invert);
}

TEST(escape_perlclass_D)
{
  PROPAGATE(assert_cc_match("\\D", "0x0 0x2F,0x31 0x38,0x3A 0x10FFFF", 0));
  PASS();
}

TEST(escape_perlclass_d)
{
  PROPAGATE(assert_cc_match("\\d", "0x30 0x30,0x39 0x39", 0));
  PASS();
}

TEST(escape_perlclass_S)
{
  PROPAGATE(
      assert_cc_match("\\S", "0x0 0x8,0xB 0xB,0xE 0x1F,0x21 0x10FFFF", 0));
  PASS();
}

TEST(escape_perlclass_s)
{
  PROPAGATE(assert_cc_match("\\s", "0x9 0xA,0xC 0xD,0x20 0x20", 0));
  PASS();
}

TEST(escape_perlclass_W)
{
  PROPAGATE(
      assert_cc_match("\\W", "0x0 0x2F,0x3A 0x40,0x5B 0x60,0x7B 0x10FFFF", 0));
  PASS();
}

TEST(escape_perlclass_w)
{
  PROPAGATE(assert_cc_match("\\w", "0x30 0x39,0x41 0x5A,0x61 0x7A", 0));
  PASS();
}

SUITE(escape_perlclass)
{
  RUN_TEST(escape_perlclass_D);
  RUN_TEST(escape_perlclass_d);
  RUN_TEST(escape_perlclass_S);
  RUN_TEST(escape_perlclass_s);
  RUN_TEST(escape_perlclass_W);
  RUN_TEST(escape_perlclass_w);
}

/*t Generated by `unicode_data.py gen_ascii_charclasses test` */

/*T Generated by `unicode_data.py gen_parser_fuzz_regression_tests` */
TEST(fuzz_regression_0000)
{
  PROPAGATE(check_noparse_n("\\&\n\xC3", 4));
  PASS();
}

TEST(fuzz_regression_0001)
{
  const char *regexes[] = {
      "\\+|(?:\x14|\x1F){0,0}",
  };
  size_t regexes_n[] = {
      15,
  };
  PROPAGATE(
      check_matches_n(regexes, regexes_n, 1, "+", 1, 0, 0, 'B', NULL, NULL, 1));
  PASS();
}

TEST(fuzz_regression_0002)
{
  const char *regexes[] = {
      "\xC3\x9A|\\$|\xC2\x81|e*",
  };
  size_t regexes_n[] = {
      11,
  };
  PROPAGATE(
      check_matches_n(regexes, regexes_n, 1, "$", 1, 0, 0, 'B', NULL, NULL, 1));
  PASS();
}

SUITE(fuzz_regression)
{
  RUN_TEST(fuzz_regression_0000);
  RUN_TEST(fuzz_regression_0001);
  RUN_TEST(fuzz_regression_0002);
}

/*t Generated by `unicode_data.py gen_parser_fuzz_regression_tests` */
