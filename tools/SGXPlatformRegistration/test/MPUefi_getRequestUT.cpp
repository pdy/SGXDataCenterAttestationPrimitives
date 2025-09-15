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
#include <cstring>

#include <MPUefi.h>
#include <UefiVar.h>

#include "TestUtils.hpp"

namespace {

ACTION_P(SaveArg0Value, p)
{
  *p = arg0;
}

} // namespace

struct GetRequestTestInput_PMV1
{
  const char *description {nullptr};

  SgxUefiVar uefiVar;
  size_t varDataSize;

  MpResult expectedResult;
};

struct GetRequestTestInput_PMV2
{
  const char *description {nullptr};

  S3mUefiVar uefiVar;
  size_t varDataSize;

  MpResult expectedResult;
};

inline std::ostream& operator<<(std::ostream &oss, const GetRequestTestInput_PMV1 &in)
{
  if(in.description)
    return oss << in.description;

  return oss;
}

inline std::ostream& operator<<(std::ostream &oss, const GetRequestTestInput_PMV2 &in)
{
  if(in.description)
    return oss << in.description;

  return oss;
}

class MPUefi_getRequest_PMV1 : public ::testing::TestWithParam<GetRequestTestInput_PMV1>
{};

class MPUefi_getRequest_PMV2 : public ::testing::TestWithParam<GetRequestTestInput_PMV2>
{};

TEST(MPUefiUT_getRequest, onNullptr)
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

  uint8_t resultRequest[1024] = {0};
  uint32_t resultRequestSize = 0;
  const auto actualResult = underTest.getRequest(resultRequest, resultRequestSize);

  // THEN
  EXPECT_STREQ(UEFI_VAR_SERVER_REQUEST, actualArg0);
  EXPECT_EQ(actualResult, MpResult::MP_NO_PENDING_DATA);
}

TEST_P(MPUefi_getRequest_PMV1, onNonNullptrReturned_PM_V1)
{
  // GIVEN
  const auto input { GetParam() };
  auto uefiVar = test::createVariable<SgxUefiVar>();
  memcpy(uefiVar.var, &input.uefiVar, sizeof(SgxUefiVar));

  const char *actualArg0 = nullptr;

  auto *uefiMock = test::getUefiMock();
  EXPECT_CALL(*uefiMock, readUEFIVar(testing::_, ::testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
          SaveArg0Value(&actualArg0),
          ::testing::SetArgReferee<1>(input.varDataSize),
          ::testing::Return(uefiVar.mem)
    ));

  std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  //WHEN
  uint8_t resultRequest[1024] = {0};
  uint32_t resultRequestSize = 1024;
  const auto actualResult = underTest.getRequest(resultRequest, resultRequestSize);

  //THEN
  EXPECT_STREQ(UEFI_VAR_SERVER_REQUEST, actualArg0);
  EXPECT_EQ(actualResult, input.expectedResult);
  if(actualResult == MP_SUCCESS)
  {
    EXPECT_EQ(resultRequestSize, input.uefiVar.size);
    EXPECT_EQ(
        0,
        std::memcmp(
          resultRequest,
          static_cast<void*>(const_cast<StructureHeader*>(&input.uefiVar.header)),
          input.uefiVar.size
        )
    );
  }
}

TEST_P(MPUefi_getRequest_PMV2, onNonNullptrReturned_PM_V2)
{
  // GIVEN
  const auto input { GetParam() };
  auto uefiVar = test::createVariable<S3mUefiVar>();
  memcpy(uefiVar.var, &input.uefiVar, sizeof(S3mUefiVar));

  const char *actualArg0 = nullptr;

  auto *uefiMock = test::getUefiMock();
  EXPECT_CALL(*uefiMock, readUEFIVar(testing::_, ::testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
          SaveArg0Value(&actualArg0),
          ::testing::SetArgReferee<1>(input.varDataSize),
          ::testing::Return(uefiVar.mem)
    ));

  std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  //WHEN
  uint8_t resultRequest[1024] = {0};
  uint32_t resultRequestSize = 1024;
  const auto actualResult = underTest.getRequest(resultRequest, resultRequestSize);

  //THEN
  EXPECT_STREQ(UEFI_VAR_SERVER_REQUEST, actualArg0);
  EXPECT_EQ(actualResult, input.expectedResult);

  if(actualResult == MP_SUCCESS)
  {
    EXPECT_EQ(resultRequestSize, input.uefiVar.size);
    EXPECT_EQ(
        0,
        std::memcmp(
          resultRequest,
          static_cast<void*>(const_cast<TlvHeader*>(&input.uefiVar.header)),
          input.uefiVar.size
        )
    );
  }
}

#ifdef _WIN32
// old 1.8.0 version
#define GTEST_TEST_CASE_P INSTANTIATE_TEST_CASE_P
#else
#define GTEST_TEST_CASE_P INSTANTIATE_TEST_SUITE_P
#endif

GTEST_TEST_CASE_P(
  MPUefi,
  MPUefi_getRequest_PMV2,
  ::testing::Values(

    GetRequestTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 Invalid size",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3, // version
          5, //size
          TlvHeader{}
        },
        PlatformManifest_GUID
      ),
      4 + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    GetRequestTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 Insufficient memory",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3, // version
          1025, //size
          TlvHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(TlvHeader) + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    GetRequestTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 Success",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3, // version
          5, //size
          TlvHeader{}
        },
        PlatformManifest_GUID
      ),
      5 + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpResult::MP_SUCCESS
    },

    GetRequestTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 Valid sizes",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3, // version
          sizeof(TlvHeader), //size
          TlvHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(TlvHeader) + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpResult::MP_SUCCESS
    }

  )
);

GTEST_TEST_CASE_P(
  MPUefi,
  MPUefi_getRequest_PMV1,
  ::testing::Values(

    GetRequestTestInput_PMV1{
      "MP_BIOS_UEFI_VARIABLE_VERSION_1 Invalid size",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1, // version
          5, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      4 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    GetRequestTestInput_PMV1{
      "MP_BIOS_UEFI_VARIABLE_VERSION_2 Invalid size",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2, // version
          5, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      4 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    GetRequestTestInput_PMV1{
      "MP_BIOS_UEFI_VARIABLE_VERSION_1 Insufficent memory",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1, // version
          1025, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      1025 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpResult::MP_USER_INSUFFICIENT_MEM
    },

    GetRequestTestInput_PMV1{
      "MP_BIOS_UEFI_VARIABLE_VERSION_2 Insufficient memory",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2, // version
          1025, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      1025 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpResult::MP_USER_INSUFFICIENT_MEM
    },

    GetRequestTestInput_PMV1{
      "Invalid MP_BIOS_VERSION",
      test::withManifest(
        SgxUefiVar{
          100, // version
          5, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpResult::MP_INVALID_PARAMETER
    },

    GetRequestTestInput_PMV1{
      "MP_BIOS_UEFI_VARIABLE_VERSION_1",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          5, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpResult::MP_SUCCESS
    },

    GetRequestTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_1 valid sizes",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          sizeof(StructureHeader), //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(StructureHeader) + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpResult::MP_SUCCESS
    }
  )
);
