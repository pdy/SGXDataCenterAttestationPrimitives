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

#include <MPUefi.h>
#include <UefiVar.h>

#include "TestUtils.hpp"

namespace {

MpRegistrationStatus createRegStatus(MpTaskStatus regiStatus, MpTaskStatus packageInfoStatus, RegistrationErrorCode errCode)
{
  MpRegistrationStatus ret;

  ret.registrationStatus = static_cast<bool>(regiStatus);
  ret.packageInfoStatus = static_cast<bool>(packageInfoStatus);
  ret.errorCode = errCode;

  return ret;
}

RegistrationStatusUEFI createStatusUefi(uint16_t version, uint16_t size, bool regiStatus, bool packageInfoStatus, uint8_t errCode)
{
  RegistrationStatusUEFI ret;

  ret.version = version;
  ret.size = size;
  ret.registrationStatus = regiStatus;
  ret.packageInfoStatus = packageInfoStatus;
  ret.errorCode = errCode;

  return ret;
}

ACTION_P(SaveArg0, p)
{
  *p = arg0;
}

ACTION_P(SaveArg1AsTestVar, p)
{
  auto statusUefiVar = test::createVariable<RegistrationStatusUEFI>();
  memcpy(statusUefiVar.mem, arg1, sizeof(RegistrationStatusUEFI));

  *p = statusUefiVar;
}

} // namespace

struct SetRegiStatusTestInput
{
  const char *desc {nullptr};
  MpRegistrationStatus inputStatus;

  RegistrationStatusUEFI expected;
  int numOfBytesToreturn;

  MpResult result;
};

inline std::ostream& operator<<(std::ostream &oss, const SetRegiStatusTestInput &in)
{
  if(in.desc)
    return oss << in.desc;

  return oss;
}

class MPUefiUT_setRegistrationStatus : public ::testing::TestWithParam<SetRegiStatusTestInput>
{};

TEST_P(MPUefiUT_setRegistrationStatus, test)
{
  // GIVEN
  const auto input { GetParam() };

  const char *actualVarName {nullptr};
  test::Variable<RegistrationStatusUEFI> actualRegUefiStatus;
  const auto varGuard = test::createVarGuard(actualRegUefiStatus);

  auto *uefiMock = test::getUefiMock(LogLevel::MP_REG_LOG_LEVEL_NONE);
  EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, sizeof(input.expected), false))
    .Times(::testing::Exactly(1))
    .WillOnce(::testing::DoAll(
          SaveArg0(&actualVarName),
          SaveArg1AsTestVar(&actualRegUefiStatus),
          ::testing::Return(input.numOfBytesToreturn)
    ));

  std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  // WHEN
  const auto actualResult = underTest.setRegistrationStatus(input.inputStatus);

  // THEN
  EXPECT_EQ(actualResult, input.result);
  EXPECT_STREQ(actualVarName, UEFI_VAR_STATUS);

  //  checks one entry at the time gives better logging when something fails
  EXPECT_EQ(actualRegUefiStatus->errorCode, input.expected.errorCode);
  EXPECT_EQ(actualRegUefiStatus->packageInfoStatus, input.expected.packageInfoStatus);
  EXPECT_EQ(actualRegUefiStatus->registrationStatus, input.expected.registrationStatus);
  EXPECT_EQ(actualRegUefiStatus->size, input.expected.size);
  EXPECT_EQ(actualRegUefiStatus->version, input.expected.version);
}

#ifdef _WIN32
// old 1.8.0 version
#define GTEST_TEST_CASE_P INSTANTIATE_TEST_CASE_P
#else
#define GTEST_TEST_CASE_P INSTANTIATE_TEST_SUITE_P
#endif

GTEST_TEST_CASE_P(
  MPUefi,
  MPUefiUT_setRegistrationStatus,
  ::testing::Values(

    SetRegiStatusTestInput {
      "Registration and Package info complete",
      createRegStatus(MP_TASK_COMPLETED, MP_TASK_COMPLETED, RegistrationErrorCode::MPA_SUCCESS),
      createStatusUefi(
        MP_BIOS_UEFI_VARIABLE_VERSION_1,
        sizeof(RegistrationStatusUEFI::status) + sizeof(RegistrationStatusUEFI::errorCode),
        true, true, // regi status, package info status
        RegistrationErrorCode::MPA_SUCCESS
      ),
      sizeof(RegistrationStatusUEFI), // numBytesToReturn
      MpResult::MP_SUCCESS
    },

    SetRegiStatusTestInput {
      "Registration completed, Package info in progress",
      createRegStatus(MP_TASK_COMPLETED, MP_TASK_IN_PROGRESS, RegistrationErrorCode::MPA_SUCCESS),
      createStatusUefi(
        MP_BIOS_UEFI_VARIABLE_VERSION_1,
        sizeof(RegistrationStatusUEFI::status) + sizeof(RegistrationStatusUEFI::errorCode),
        true, false, // regi status, package info status
        RegistrationErrorCode::MPA_SUCCESS
      ),
      sizeof(RegistrationStatusUEFI), // numBytesToReturn
      MpResult::MP_SUCCESS
    },

    SetRegiStatusTestInput {
      "Registration in progress, Package info completer",
      createRegStatus(MP_TASK_IN_PROGRESS, MP_TASK_COMPLETED, RegistrationErrorCode::MPA_SUCCESS),
      createStatusUefi(
        MP_BIOS_UEFI_VARIABLE_VERSION_1,
        sizeof(RegistrationStatusUEFI::status) + sizeof(RegistrationStatusUEFI::errorCode),
        false, true, // regi status, package info status
        RegistrationErrorCode::MPA_SUCCESS
      ),
      sizeof(RegistrationStatusUEFI), // numBytesToReturn
      MpResult::MP_SUCCESS
    },

    SetRegiStatusTestInput {
      "Registration in progress, Package info in progress",
      createRegStatus(MP_TASK_IN_PROGRESS, MP_TASK_IN_PROGRESS, RegistrationErrorCode::MPA_SUCCESS),
      createStatusUefi(
        MP_BIOS_UEFI_VARIABLE_VERSION_1,
        sizeof(RegistrationStatusUEFI::status) + sizeof(RegistrationStatusUEFI::errorCode),
        false, false, // regi status, package info status
        RegistrationErrorCode::MPA_SUCCESS
      ),
      sizeof(RegistrationStatusUEFI), // numBytesToReturn
      MpResult::MP_SUCCESS
    },

    SetRegiStatusTestInput {
      "Insufficient privileges status check",
      createRegStatus(MP_TASK_IN_PROGRESS, MP_TASK_IN_PROGRESS, RegistrationErrorCode::MPA_SUCCESS),
      createStatusUefi(
        MP_BIOS_UEFI_VARIABLE_VERSION_1,
        sizeof(RegistrationStatusUEFI::status) + sizeof(RegistrationStatusUEFI::errorCode),
        false, false, // regi status, package info status
        RegistrationErrorCode::MPA_SUCCESS
      ),
      -1, // numBytesToReturn -1 causes insufficient privileges status
      MpResult::MP_INSUFFICIENT_PRIVILEGES
    },

    SetRegiStatusTestInput {
      "Internal error when returned bytes count is less than expected",
      createRegStatus(MP_TASK_IN_PROGRESS, MP_TASK_IN_PROGRESS, RegistrationErrorCode::MPA_SUCCESS),
      createStatusUefi(
        MP_BIOS_UEFI_VARIABLE_VERSION_1,
        sizeof(RegistrationStatusUEFI::status) + sizeof(RegistrationStatusUEFI::errorCode),
        false, false, // regi status, package info status
        RegistrationErrorCode::MPA_SUCCESS
      ),
      sizeof(RegistrationStatusUEFI) - 1, // numBytesToReturn
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    SetRegiStatusTestInput {
      "Internal error when returned bytes count is higher than expected",
      createRegStatus(MP_TASK_IN_PROGRESS, MP_TASK_IN_PROGRESS, RegistrationErrorCode::MPA_SUCCESS),
      createStatusUefi(
        MP_BIOS_UEFI_VARIABLE_VERSION_1,
        sizeof(RegistrationStatusUEFI::status) + sizeof(RegistrationStatusUEFI::errorCode),
        false, false, // regi status, package info status
        RegistrationErrorCode::MPA_SUCCESS
      ),
      sizeof(RegistrationStatusUEFI) + 1, // numBytesToReturn
      MpResult::MP_UEFI_INTERNAL_ERROR
    }

  )
);
