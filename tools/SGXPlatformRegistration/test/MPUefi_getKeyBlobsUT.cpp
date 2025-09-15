/*
 * Copyright (C) 2025 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <ostream>

#include <MPUefi.h>
#include <UefiVar.h>

#include "TestUtils.hpp"

namespace {

ACTION_P(SaveArg0Value, p)
{
  *p = arg0;
}

} // namespace


struct GetKeyBlobs_PMV1
{
  const char *description {nullptr};

  SgxUefiVar uefiVar;
  size_t varDataSize;

  MpRequestType expectedRetRequestType;
  MpResult expectedResult;
};

struct GetKeyBlobs_PMV2
{
  const char *description {nullptr};

  S3mUefiVar uefiVar;
  size_t varDataSize;

  MpRequestType expectedRetRequestType;
  MpResult expectedResult;
};

inline std::ostream& operator<<(std::ostream &oss, const GetKeyBlobs_PMV1 &in)
{
  if(in.description)
    return oss << in.description;

  return oss;
}

inline std::ostream& operator<<(std::ostream &oss, const GetKeyBlobs_PMV2 &in)
{
  if(in.description)
    return oss << in.description;

  return oss;
}

TEST(MPUefiUT_getKeyBlobs, onNullptr)
{
  // GIVEN
  const char *actualArg0 = nullptr;

  auto *uefiMock = test::getUefiMock();
  EXPECT_CALL(*uefiMock, readUEFIVar(::testing::_, ::testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
          SaveArg0Value(&actualArg0),
          ::testing::Return(nullptr)
    ));

  std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  // WHEN

  uint8_t resultKeyBlobs[1024] = {0};
  uint16_t resultBlobsSize = 0;
  const auto actualResult = underTest.getKeyBlobs(resultKeyBlobs, resultBlobsSize);

  // THEN
  EXPECT_STREQ(UEFI_VAR_PACKAGE_INFO, actualArg0);
  EXPECT_EQ(actualResult, MpResult::MP_NO_PENDING_DATA);
}
