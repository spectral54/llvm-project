// RUN: %clang_asan -O2 %s -o %t
// RUN: %run %t test1 2>&1 | FileCheck %s --check-prefix=TEST1
// RUN: %run %t test2 2>&1 | FileCheck %s --check-prefix=TEST2
// FIXME: test3 should not fail.
// RUN: not %run %t test3 2>&1 | FileCheck %s --check-prefix=TEST3
// RUN: not %run %t test4 2>&1 | FileCheck %s --check-prefix=TEST4

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sanitizer/asan_interface.h>

void regexec_or_exit(const regex_t *preg, const char *str, size_t nmatch,
                     regmatch_t pmatch[], int eflags) {
  int err = regexec(preg, str, nmatch, pmatch, eflags);
  if (err != 0) {
    printf("Error in regexec: %d\n", err);
    exit(1);
  }
}

// TEST1: MATCHED: ABCDEF
void test1(regex_t *re) {
  regmatch_t match[1];
  char str[] = "ABCDEF";

  // Check that regexec works fine under Asan.
  regexec_or_exit(re, str, /*nmatch=*/1, /*pmatch=*/match, /*flags=*/0);
  printf("MATCHED: %.*s\n", match[0].rm_eo - match[0].rm_so,
         str + match[0].rm_so);
}

// TEST2: MATCHED: BC
void test2(regex_t *re) {
#ifndef REG_STARTEND
  // Print the expected line if REG_STARTEND is unavailable
  printf("MATCHED: BC\n");
  return;
#else
  regmatch_t match[1];
  char str[] = "ABCDEF";

  // Test basic functionality of REG_STARTEND.
  match[0].rm_so = 1;
  match[0].rm_eo = 3;
  regexec_or_exit(re, str, /*nmatch=*/1, /*pmatch=*/match,
                  /*flags=*/REG_STARTEND);
  printf("MATCHED: %.*s\n", match[0].rm_eo - match[0].rm_so,
         str + match[0].rm_so);
#endif
}

// FIXME: This should be 'MATCHED: CD', not an asan failure.
// TEST3: use-after-poison
void test3(regex_t *re) {
#ifndef REG_STARTEND
  // Print the expected line if REG_STARTEND is unavailable
  printf("MATCHED: CD\n");
  return;
#else
  regmatch_t match[1];

  // Check that asan itself doesn't do the wrong thing and interact with/mask
  // memory outside of the specified region.
  char buf[200] = {'X'};
  memset(buf, 'X', 200);
  strcpy(&buf[64], "ABCDEFGH");
  __asan_poison_memory_region(buf, sizeof(buf));
  // asan has an internal 'scale'. It's currently set to 3, meaning 8 bytes
  // minimum granularity, so this 2 is actually rounding up to 8 (and
  // potentially 16, if it straddles a boundary).
  __asan_unpoison_memory_region(&buf[66], 2);

  match[0].rm_so = 66;
  match[0].rm_eo = 68;
  regexec_or_exit(re, buf, /*nmatch=*/1, /*pmatch=*/match,
                  /*flags=*/REG_STARTEND);
  printf("MATCHED: %.*s\n", match[0].rm_eo - match[0].rm_so,
         buf + match[0].rm_so);
#endif
}

// TEST4: use-after-poison
void test4(regex_t *re) {
#ifndef REG_STARTEND
  // Print the expected line if REG_STARTEND is unavailable
  printf("use-after-poison");
  return;
#else
  regmatch_t match[1];

  // Check that asan correctly detects strings that are poisoned.
  char buf[200];
  memset(buf, 'X', 200);
  strcpy(&buf[64], "ABCDEFGH");
  __asan_poison_memory_region(buf, sizeof(buf));
  // asan has an internal 'scale'. It's currently set to 3, meaning 8 bytes
  // minimum granularity, so this 2 is actually rounding up to 8 (and
  // potentially 16, if it straddles a boundary).
  __asan_unpoison_memory_region(&buf[66], 2);

  match[0].rm_so = 60;  // 4 bytes before the unpoisoned region
  match[0].rm_eo = 68;  // end of unpoisoned region
  regexec_or_exit(re, buf, /*nmatch=*/1, /*pmatch=*/match,
                  /*flags=*/REG_STARTEND);
  // Don't trigger asan reports from the printf itself. If the regexec didn't
  // catch it, we should fail.
  __asan_unpoison_memory_region(buf, sizeof(buf));
  printf("MATCHED: %.*s\n", match[0].rm_eo - match[0].rm_so,
         buf + match[0].rm_so);
#endif
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Invalid number of arguments\n");
    exit(1);
  }

  regex_t re;
  int err = regcomp(&re, ".*", 0);
  if (err != 0) {
    printf("Error in regcomp: %d\n", err);
    exit(1);
  }

  int ret = 0;

  if (!strcmp(argv[1], "test1"))
    test1(&re);
  else if (!strcmp(argv[1], "test2"))
    test2(&re);
  else if (!strcmp(argv[1], "test3"))
    test3(&re);
  else if (!strcmp(argv[1], "test4"))
    test4(&re);
  else {
    printf("Error: %s not a valid test", argv[1]);
    ret = 1;
  }

  regfree(&re);

  return ret;
}
