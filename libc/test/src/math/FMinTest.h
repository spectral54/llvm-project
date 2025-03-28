//===-- Utility class to test fmin[f|l] -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_TEST_SRC_MATH_FMINTEST_H
#define LLVM_LIBC_TEST_SRC_MATH_FMINTEST_H

#include "src/__support/FPUtil/FPBits.h"
#include "test/UnitTest/FEnvSafeTest.h"
#include "test/UnitTest/FPMatcher.h"
#include "test/UnitTest/Test.h"
#include "utils/MPFRWrapper/MPFRUtils.h"

#include "hdr/math_macros.h"

namespace mpfr = LIBC_NAMESPACE::testing::mpfr;

template <typename T>
class FMinTest : public LIBC_NAMESPACE::testing::FEnvSafeTest {

  DECLARE_SPECIAL_CONSTANTS(T)

public:
  typedef T (*FMinFunc)(T, T);

  void testNaN(FMinFunc func) {
    EXPECT_FP_EQ(inf, func(aNaN, inf));
    EXPECT_FP_EQ(neg_inf, func(neg_inf, aNaN));
    EXPECT_FP_EQ(zero, func(aNaN, zero));
    EXPECT_FP_EQ(neg_zero, func(neg_zero, aNaN));
    EXPECT_FP_EQ(T(-1.2345), func(aNaN, T(-1.2345)));
    EXPECT_FP_EQ(T(1.2345), func(T(1.2345), aNaN));
    EXPECT_FP_EQ(aNaN, func(aNaN, aNaN));
  }

  void testInfArg(FMinFunc func) {
    EXPECT_FP_EQ(neg_inf, func(neg_inf, inf));
    EXPECT_FP_EQ(zero, func(inf, zero));
    EXPECT_FP_EQ(neg_zero, func(neg_zero, inf));
    EXPECT_FP_EQ(T(1.2345), func(inf, T(1.2345)));
    EXPECT_FP_EQ(T(-1.2345), func(T(-1.2345), inf));
  }

  void testNegInfArg(FMinFunc func) {
    EXPECT_FP_EQ(neg_inf, func(inf, neg_inf));
    EXPECT_FP_EQ(neg_inf, func(neg_inf, zero));
    EXPECT_FP_EQ(neg_inf, func(neg_zero, neg_inf));
    EXPECT_FP_EQ(neg_inf, func(neg_inf, T(-1.2345)));
    EXPECT_FP_EQ(neg_inf, func(T(1.2345), neg_inf));
  }

  void testBothZero(FMinFunc func) {
    EXPECT_FP_EQ(zero, func(zero, zero));
    EXPECT_FP_EQ(neg_zero, func(neg_zero, zero));
    EXPECT_FP_EQ(neg_zero, func(zero, neg_zero));
    EXPECT_FP_EQ(neg_zero, func(neg_zero, neg_zero));
  }

  void testRange(FMinFunc func) {
    constexpr StorageType COUNT = 100'001;
    constexpr StorageType STEP = STORAGE_MAX / COUNT;
    for (StorageType i = 0, v = 0, w = STORAGE_MAX; i <= COUNT;
         ++i, v += STEP, w -= STEP) {
      T x = FPBits(v).get_val(), y = FPBits(w).get_val();
      if (FPBits(v).is_nan() || FPBits(v).is_inf())
        continue;
      if (FPBits(w).is_nan() || FPBits(w).is_inf())
        continue;
      if ((x == 0) && (y == 0))
        continue;

      if (x > y) {
        EXPECT_FP_EQ(y, func(x, y));
      } else {
        EXPECT_FP_EQ(x, func(x, y));
      }
    }
  }
};

#define LIST_FMIN_TESTS(T, func)                                               \
  using LlvmLibcFMinTest = FMinTest<T>;                                        \
  TEST_F(LlvmLibcFMinTest, NaN) { testNaN(&func); }                            \
  TEST_F(LlvmLibcFMinTest, InfArg) { testInfArg(&func); }                      \
  TEST_F(LlvmLibcFMinTest, NegInfArg) { testNegInfArg(&func); }                \
  TEST_F(LlvmLibcFMinTest, BothZero) { testBothZero(&func); }                  \
  TEST_F(LlvmLibcFMinTest, Range) { testRange(&func); }

#endif // LLVM_LIBC_TEST_SRC_MATH_FMINTEST_H
