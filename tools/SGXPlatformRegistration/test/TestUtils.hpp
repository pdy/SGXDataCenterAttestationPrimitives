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

#ifndef TEST_UTILS_HPP_
#define TEST_UTILS_HPP_

#include <UefiVar.h>
#include "mocks/IUefiMock.hpp"

namespace test {

template<typename T>
struct Variable
{
  uint8_t *mem {nullptr};
  T *var {nullptr};

  T* operator->() { return var; }
};

template<typename T, typename ...Args>
inline Variable<T> createVariable(Args&& ...args)
{
  // TODO: not entirely correctly aligned for T, as there will be
  // external delete call on that (inside MPUefi.cpp for example)
  // still we have UB here - problem for later

  static constexpr size_t SIZE = sizeof(T) + sizeof(std::max_align_t);
  uint8_t *mem = new uint8_t[SIZE];
  memset(mem, 0x00, SIZE);

  auto *var = ::new(mem) T(std::forward<Args>(args)...);

  return Variable<T>{mem, var};
}

template<typename T>
[[nodiscard]] inline auto createVarGuard(Variable<T> var)
{
  struct Defer
  {
    Variable<T> var;
    ~Defer()
    {
      delete[] var.mem;
    }
  };

  return Defer{var};
}

inline test::IUefiMock *getUefiMock(LogLevel logLevel = LogLevel::MP_REG_LOG_LEVEL_NONE)
{
  test::IUefiMock *uefiMock = new test::IUefiMock;

  EXPECT_CALL(*uefiMock, getLogLevel())
    .Times(::testing::Exactly(1))
    .WillRepeatedly(::testing::Return(logLevel));

  return uefiMock;
}

inline SgxUefiVar withManifest(SgxUefiVar var, const uint8_t *manifestGuid, size_t guidSize = GUID_SIZE)
{
  if(manifestGuid)
    memcpy(var.header.guid, manifestGuid, guidSize);

  return var;
}

inline S3mUefiVar withManifest(S3mUefiVar var, const uint8_t *manifestGuid, size_t guidSize = GUID_SIZE)
{
  if(manifestGuid)
    memcpy(var.header.guid, manifestGuid, guidSize);

  return var;
}

} // namespace

#endif // TEST_UTILS_HPP_
