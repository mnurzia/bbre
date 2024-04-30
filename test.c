#include <string.h>

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

TEST(init) {
  re *r;
  r = re_init("");
  re_destroy(r);
  PASS();
}

TEST(chr) {
  ASSERT_MATCH("a", "a");
  ASSERT_MATCH("b", "b");
  ASSERT_MATCH("X", "X");
  ASSERT_NMATCH("a", "X");
  PASS();
}

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

int main(int argc, const char *const *argv) {
  MPTEST_MAIN_BEGIN_ARGS(argc, argv);
  RUN_TEST(init);
  RUN_TEST(chr);
  RUN_TEST(cat);
  RUN_TEST(quant);
  RUN_TEST(alt);
  RUN_TEST(cls);
  RUN_TEST(bounds);
  RUN_TEST(unanchored);
  MPTEST_MAIN_END();
}
