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

int main(int argc, const char *const *argv) {
  MPTEST_MAIN_BEGIN_ARGS(argc, argv);
  RUN_TEST(init);
  RUN_TEST(chr);
  RUN_TEST(cat);
  RUN_TEST(quant);
  RUN_TEST(alt);
  RUN_TEST(cls);
  MPTEST_MAIN_END();
}
