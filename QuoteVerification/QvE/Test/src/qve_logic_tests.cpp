/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <cstddef>
#include <vector>

#include "SgxEcdsaAttestation/QuoteVerification.h"
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "qve_logic.h"
#include "MockValidity.h"
#include "MockCertificate.h"
#include "MockCertificateChain.h"
#include "MockEnclaveIdentity.h"
#include "MockTcbInfo.h"

using namespace intel::sgx::dcap;
using namespace intel::sgx::dcap::parser::x509;
using namespace intel::sgx::dcap::parser::json;
using namespace testing;


TEST(QveUtilsTest, IsNonterminalError) {
    EXPECT_TRUE(is_nonterminal_error(STATUS_TCB_OUT_OF_DATE));
    EXPECT_TRUE(is_nonterminal_error(STATUS_SGX_TCB_INFO_EXPIRED));
    EXPECT_FALSE(is_nonterminal_error(static_cast<Status>(999))); // Unknown status
}

TEST(QveUtilsTest, IsExpirationError) {
    EXPECT_TRUE(is_expiration_error(STATUS_SGX_TCB_INFO_EXPIRED));
    EXPECT_TRUE(is_expiration_error(STATUS_SGX_PCK_CERT_CHAIN_EXPIRED));
    EXPECT_FALSE(is_expiration_error(STATUS_TCB_OUT_OF_DATE));
    EXPECT_FALSE(is_expiration_error(static_cast<Status>(999))); // Unknown status
}

TEST(StatusErrorToQlQveResultTest, ReturnsCorrectResult) {
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::UpToDate), SGX_QL_QV_RESULT_OK);
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::Revoked), SGX_QL_QV_RESULT_REVOKED);
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::OutOfDate), SGX_QL_QV_RESULT_OUT_OF_DATE);
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::OutOfDateConfigurationNeeded), SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED);
    EXPECT_EQ(status_error_to_ql_qve_result(json::TcbStatus::ConfigurationNeeded), SGX_QL_QV_RESULT_CONFIG_NEEDED);
    EXPECT_EQ(status_error_to_ql_qve_result(static_cast<json::TcbStatus>(-1)), SGX_QL_QV_RESULT_UNSPECIFIED);
}

TEST(ParseBytesLETest, ParseUint16) {
    // given
    uint8_t raw[] = {0x34, 0x12}; // Little-endian representation of 0x1234

    // when
    uint16_t result = parseBytesLE<uint16_t>(raw);

    // then
    EXPECT_EQ(result, 0x1234);
}

TEST(ParseBytesLETest, ParseUint32) {
    // given
    uint8_t raw[] = {0x78, 0x56, 0x34, 0x12}; // Little-endian representation of 0x12345678

    // when
    uint32_t result = parseBytesLE<uint32_t>(raw);

    // then
    EXPECT_EQ(result, 0x12345678);
}

TEST(ParseBytesLETest, ParseUint64) {
    // given
    uint8_t raw[] = {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01}; // Little-endian representation of 0x0123456789ABCDEF

    // when
    uint64_t result = parseBytesLE<uint64_t>(raw);

    // then
    EXPECT_EQ(result, 0x0123456789ABCDEF);
}

TEST(ParseBytesLETest, ParseWithOffset) {
    // given
    uint8_t raw[] = {0x00, 0x00, 0x78, 0x56, 0x34, 0x12}; // Offset to 0x12345678

    // when
    uint32_t result = parseBytesLE<uint32_t>(raw, 2);

    // then
    EXPECT_EQ(result, 0x12345678);
}

TEST(DeserializeVerCollatInfoTest, ValidInput) {
    // given
    std::vector<uint8_t> input = {
            0x01, 0x00,                                        // id = 1
            0x02, 0x00,                                        // version = 2
            0x4A, 0x7E, 0xBE, 0x68, 0x00, 0x00, 0x00, 0x00,    // issue_date_min = 0x5ED460 (Unix timestamp)
            0x01, 0x88, 0xBE, 0x68, 0x00, 0x00, 0x00, 0x00,    // issue_date_max = 0x5ED470
            0x80, 0xD4, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x00,    // expiration_date_min = 0x5ED480
            0x03, 0x00, 0x00, 0x00,                            // tcb_eval_data_num = 3
            0x90, 0xD4, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x00,    // tcb_date_min = 0x5ED490
            'A', 'B', 'C', '\0',                               // sa_list = "ABC"
            0x00                                               // Padding for MAX_SA_LIST_SIZE
    };
    verification_collateral_info_t verificationCollateralInfo;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verificationCollateralInfo);

    // then
    EXPECT_EQ(ret, SGX_QL_SUCCESS);
    EXPECT_EQ(verificationCollateralInfo.id, 1);
    EXPECT_EQ(verificationCollateralInfo.version, 2);
    EXPECT_EQ(verificationCollateralInfo.issue_date_min, 0x68BE7E4A);
    EXPECT_EQ(verificationCollateralInfo.issue_date_max, 0x68BE8801);
    EXPECT_EQ(verificationCollateralInfo.expiration_date_min, 0x5ED480);
    EXPECT_EQ(verificationCollateralInfo.tcb_eval_data_num, 3);
    EXPECT_EQ(verificationCollateralInfo.tcb_date_min, 0x5ED490);
    EXPECT_STREQ(verificationCollateralInfo.sa_list, "ABC");
}

TEST(DeserializeVerCollatInfoTest, EmptyInput) {
    // given
    std::vector<uint8_t> input;
    verification_collateral_info_t verificationCollateralInfo;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verificationCollateralInfo);

    // then
    EXPECT_EQ(ret, SGX_QL_ERROR_INVALID_PARAMETER);
}

TEST(DeserializeVerCollatInfoTest, InsufficientData) {
    // given
    std::vector<uint8_t> input = {0x01, 0x00}; // Only partial data, `id` only.
    verification_collateral_info_t verificationCollateralInfo;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verificationCollateralInfo);

    // then
    EXPECT_EQ(ret, SGX_QL_ERROR_INVALID_PARAMETER);
}

TEST(DeserializeVerCollatInfoTest, DataTooLarge) {
    // given
    std::vector<uint8_t> input(offsetof(verification_collateral_info_t, sa_list) + MAX_SA_LIST_SIZE + 1, 0); // exceeds max size.
    verification_collateral_info_t verificationCollateralInfo;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verificationCollateralInfo);

    // then
    EXPECT_EQ(ret, SGX_QL_ERROR_INVALID_PARAMETER);
}

TEST(DeserializeVerCollatInfoTest, MaxSaListSize) {
    // given
    std::vector<uint8_t> input(offsetof(verification_collateral_info_t, sa_list) + MAX_SA_LIST_SIZE, 0);
    input[offsetof(verification_collateral_info_t, sa_list)] = 'X';
    input[offsetof(verification_collateral_info_t, sa_list) + MAX_SA_LIST_SIZE - 1] = '\0';
    verification_collateral_info_t verificationCollateralInfo;

    // when
    quote3_error_t ret = deserializeVerCollatInfo(input, verificationCollateralInfo);

    // then
    EXPECT_EQ(ret, SGX_QL_SUCCESS);
    EXPECT_EQ(verificationCollateralInfo.sa_list[0], 'X');
    EXPECT_EQ(verificationCollateralInfo.sa_list[MAX_SA_LIST_SIZE - 1], '\0');
}

TEST(GetEarliestIssueDateTest, EmptyChain) {
    // given
    MockCertificateChain mockChain;
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{}));

    // when
    time_t result = getEarliestIssueDate(&mockChain);

    // then
    EXPECT_EQ(result, 0);
}

TEST(GetEarliestIssueDateTest, SingleCertificate) {
    // given
    MockCertificateChain mockChain;
    auto cert = std::make_shared<MockCertificate>();
    MockValidity mockValidity;
    time_t notBeforeTime = 1735686000; // 2025-01-01 00:00:00 UTC

    EXPECT_CALL(*cert, getValidity()).WillRepeatedly(ReturnRef(mockValidity));
    EXPECT_CALL(mockValidity, getNotBeforeTime()).WillRepeatedly(Return(notBeforeTime));
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const ::Certificate>>{cert}));

    // when
    time_t result = getEarliestIssueDate(&mockChain);

    // then
    EXPECT_EQ(result, notBeforeTime);
}

TEST(GetEarliestIssueDateTest, MultipleCertificates) {
    // given
    MockCertificateChain mockChain;
    auto cert1 = std::make_shared<MockCertificate>();
    auto cert2 = std::make_shared<MockCertificate>();
    auto cert3 = std::make_shared<MockCertificate>();
    MockValidity mockValidity1;
    MockValidity mockValidity2;
    MockValidity mockValidity3;

    time_t notBeforeEarliest = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t notBeforeMiddle = 1751320800;   // 2025-07-01 00:00:00 UTC
    time_t notBeforeLatest = 1759269600;   // 2025-10-01 00:00:00 UTC

    EXPECT_CALL(*cert1, getValidity()).WillRepeatedly(ReturnRef(mockValidity1));
    EXPECT_CALL(*cert2, getValidity()).WillRepeatedly(ReturnRef(mockValidity2));
    EXPECT_CALL(*cert3, getValidity()).WillRepeatedly(ReturnRef(mockValidity3));
    EXPECT_CALL(mockValidity1, getNotBeforeTime()).WillRepeatedly(Return(notBeforeEarliest));
    EXPECT_CALL(mockValidity2, getNotBeforeTime()).WillRepeatedly(Return(notBeforeMiddle));
    EXPECT_CALL(mockValidity3, getNotBeforeTime()).WillRepeatedly(Return(notBeforeLatest));
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert1, cert2, cert3}));

    // when
    time_t result = getEarliestIssueDate(&mockChain);

    // then
    EXPECT_EQ(result, notBeforeEarliest);
}

TEST(GetEarliestExpirationDateTest, EmptyChain) {
    // given
    MockCertificateChain mockChain;
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{}));

    // when
    time_t result = getEarliestExpirationDate(&mockChain);

    // then
    EXPECT_EQ(result, 0);
}

TEST(GetEarliestExpirationDateTest, SingleCertificate) {
    // given
    MockCertificateChain mockChain;
    auto cert = std::make_shared<MockCertificate>();
    MockValidity mockValidity;
    time_t notAfterTime = 1735686000; // 2025-01-01 00:00:00 UTC

    EXPECT_CALL(*cert, getValidity()).WillRepeatedly(ReturnRef(mockValidity));
    EXPECT_CALL(mockValidity, getNotAfterTime()).WillRepeatedly(Return(notAfterTime));
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert}));

    // when
    time_t result = getEarliestExpirationDate(&mockChain);

    // then
    EXPECT_EQ(result, notAfterTime);
}

TEST(GetEarliestExpirationDateTest, MultipleCertificates) {
    // given
    MockCertificateChain mockChain;
    auto cert1 = std::make_shared<MockCertificate>();
    auto cert2 = std::make_shared<MockCertificate>();
    auto cert3 = std::make_shared<MockCertificate>();
    MockValidity mockValidity1;
    MockValidity mockValidity2;
    MockValidity mockValidity3;

    time_t notAfterEarliest = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t notAfterMiddle = 1751320800;   // 2025-07-01 00:00:00 UTC
    time_t notAfterLatest = 1759269600;   // 2025-10-01 00:00:00 UTC

    EXPECT_CALL(*cert1, getValidity()).WillRepeatedly(ReturnRef(mockValidity1));
    EXPECT_CALL(*cert2, getValidity()).WillRepeatedly(ReturnRef(mockValidity2));
    EXPECT_CALL(*cert3, getValidity()).WillRepeatedly(ReturnRef(mockValidity3));
    EXPECT_CALL(mockValidity1, getNotAfterTime()).WillRepeatedly(Return(notAfterEarliest));
    EXPECT_CALL(mockValidity2, getNotAfterTime()).WillRepeatedly(Return(notAfterMiddle));
    EXPECT_CALL(mockValidity3, getNotAfterTime()).WillRepeatedly(Return(notAfterLatest));
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert1, cert2, cert3}));

    // when
    time_t result = getEarliestExpirationDate(&mockChain);

    // then
    EXPECT_EQ(result, notAfterEarliest);
}

TEST(GetLatestIssueDateTest, EmptyChain) {
    // given
    MockCertificateChain mockChain;
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{}));

    // when
    time_t result = getLatestIssueDate(&mockChain);

    // then
    EXPECT_EQ(result, 0);
}

TEST(GetLatestIssueDateTest, SingleCertificate) {
    // given
    MockCertificateChain mockChain;
    auto cert = std::make_shared<MockCertificate>();
    MockValidity mockValidity;
    time_t notBeforeTime = 1735686000; // 2025-01-01 00:00:00 UTC

    EXPECT_CALL(*cert, getValidity()).WillRepeatedly(ReturnRef(mockValidity));
    EXPECT_CALL(mockValidity, getNotBeforeTime()).WillRepeatedly(Return(notBeforeTime));
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert}));

    // when
    time_t result = getLatestIssueDate(&mockChain);

    // then
    EXPECT_EQ(result, notBeforeTime);
}

TEST(GetLatestIssueDateTest, MultipleCertificates) {
    // given
    MockCertificateChain mockChain;
    auto cert1 = std::make_shared<MockCertificate>();
    auto cert2 = std::make_shared<MockCertificate>();
    auto cert3 = std::make_shared<MockCertificate>();
    MockValidity mockValidity1;
    MockValidity mockValidity2;
    MockValidity mockValidity3;

    time_t notBeforeEarliest = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t notBeforeMiddle = 1751320800;   // 2025-07-01 00:00:00 UTC
    time_t notBeforeLatest = 1759269600;   // 2025-10-01 00:00:00 UTC

    EXPECT_CALL(*cert1, getValidity()).WillRepeatedly(ReturnRef(mockValidity1));
    EXPECT_CALL(*cert2, getValidity()).WillRepeatedly(ReturnRef(mockValidity2));
    EXPECT_CALL(*cert3, getValidity()).WillRepeatedly(ReturnRef(mockValidity3));
    EXPECT_CALL(mockValidity1, getNotBeforeTime()).WillRepeatedly(Return(notBeforeEarliest));
    EXPECT_CALL(mockValidity2, getNotBeforeTime()).WillRepeatedly(Return(notBeforeMiddle));
    EXPECT_CALL(mockValidity3, getNotBeforeTime()).WillRepeatedly(Return(notBeforeLatest));
    EXPECT_CALL(mockChain, getCerts()).WillOnce(Return(std::vector<std::shared_ptr<const Certificate>>{cert1, cert2, cert3}));

    // when
    time_t result = getLatestIssueDate(&mockChain);

    // then
    EXPECT_EQ(result, notBeforeLatest);
}

class QveGetCollateralDatesTest : public ::testing::Test {
protected:
    MockEnclaveIdentity mockEnclaveIdentity;
    MockTcbInfo mockTcbInfo;
    MockCertificateChain mockCertificateChain;
    _sgx_ql_qve_collateral_t mockCollateral;
    std::string mockChain;
    time_t earliestIssueDate;
    time_t latestIssueDate;
    time_t earliestExpirationDate;

    void SetUp() override {
        earliestIssueDate = 0;
        latestIssueDate = 0;
        earliestExpirationDate = 0;
        mockCollateral = {};
        mockChain = "mock_chain";
    }
};

TEST_F(QveGetCollateralDatesTest, NullParameters) {
    // given

    // when
    auto result = qve_get_collateral_dates(mockEnclaveIdentity, mockCertificateChain, nullptr, nullptr, nullptr, nullptr, nullptr);

    // then
    EXPECT_EQ(result, SGX_QL_ERROR_INVALID_PARAMETER);
}

TEST_F(QveGetCollateralDatesTest, IssuerChainParseError) {
    // given
    mockCollateral.qe_identity_issuer_chain = &mockChain[0]; 
    EXPECT_CALL(mockCertificateChain, parse(mockChain)).WillOnce(Return(STATUS_SGX_ROOT_CA_INVALID));

    // when
    auto result = qve_get_collateral_dates(mockEnclaveIdentity, mockCertificateChain, &mockTcbInfo, &mockCollateral, &earliestIssueDate, &latestIssueDate, &earliestExpirationDate);

    // then
    EXPECT_EQ(result, SGX_QL_PCK_CERT_CHAIN_ERROR);
}

TEST_F(QveGetCollateralDatesTest, UnsupportedEnclaveIdentityVersion) {
    // given
    mockCollateral.qe_identity_issuer_chain = &mockChain[0];
    EXPECT_CALL(mockCertificateChain, parse(mockChain)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(mockEnclaveIdentity, getVersion()).WillOnce(Return(1)); // Unsupported version

    // when
    auto result = qve_get_collateral_dates(mockEnclaveIdentity, mockCertificateChain, &mockTcbInfo, &mockCollateral, &earliestIssueDate, &latestIssueDate, &earliestExpirationDate);

    // then
    EXPECT_EQ(result, SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT);
}

TEST_F(QveGetCollateralDatesTest, UnsupportedTcbInfoVersion) {
    // given

    mockCollateral.qe_identity_issuer_chain = &mockChain[0];
    EXPECT_CALL(mockCertificateChain, parse(mockChain)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(mockEnclaveIdentity, getVersion()).WillOnce(Return(2)); // Supported version
    EXPECT_CALL(mockTcbInfo, getVersion()).WillOnce(Return(1));         // Unsupported version

    // when
    auto result = qve_get_collateral_dates(mockEnclaveIdentity, mockCertificateChain, &mockTcbInfo, &mockCollateral, &earliestIssueDate, &latestIssueDate, &earliestExpirationDate);

    // then
    EXPECT_EQ(result, SGX_QL_TCBINFO_UNSUPPORTED_FORMAT);
}

TEST_F(QveGetCollateralDatesTest, ValidCollateralDates) {
    // given
    auto cert1 = std::make_shared<MockCertificate>();
    auto cert2 = std::make_shared<MockCertificate>();
    auto cert3 = std::make_shared<MockCertificate>();
    MockValidity mockValidity1;
    MockValidity mockValidity2;
    MockValidity mockValidity3;

    time_t notBeforeEarliest = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t notBeforeMiddle = 1751320800;   // 2025-07-01 00:00:00 UTC
    time_t notBeforeLatest = 1759269600;   // 2025-10-01 00:00:00 UTC
    time_t notAfterEarliest = 1735686000; // 2025-01-01 00:00:00 UTC
    time_t notAfterMiddle = 1751320800;   // 2025-07-01 00:00:00 UTC
    time_t notAfterLatest = 1759269600;   // 2025-10-01 00:00:00 UTC

    mockCollateral.qe_identity_issuer_chain = &mockChain[0];
    EXPECT_CALL(mockCertificateChain, parse(mockChain)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(mockEnclaveIdentity, getVersion()).WillOnce(Return(2)); // Supported version
    EXPECT_CALL(mockTcbInfo, getVersion()).WillOnce(Return(2));         // Supported version

    EXPECT_CALL(*cert1, getValidity()).WillRepeatedly(ReturnRef(mockValidity1));
    EXPECT_CALL(*cert2, getValidity()).WillRepeatedly(ReturnRef(mockValidity2));
    EXPECT_CALL(*cert3, getValidity()).WillRepeatedly(ReturnRef(mockValidity3));
    EXPECT_CALL(mockValidity1, getNotBeforeTime()).WillRepeatedly(Return(notBeforeEarliest));
    EXPECT_CALL(mockValidity2, getNotBeforeTime()).WillRepeatedly(Return(notBeforeMiddle));
    EXPECT_CALL(mockValidity3, getNotBeforeTime()).WillRepeatedly(Return(notBeforeLatest));
    EXPECT_CALL(mockValidity1, getNotAfterTime()).WillRepeatedly(Return(notAfterEarliest));
    EXPECT_CALL(mockValidity2, getNotAfterTime()).WillRepeatedly(Return(notAfterMiddle));
    EXPECT_CALL(mockValidity3, getNotAfterTime()).WillRepeatedly(Return(notAfterLatest));
    EXPECT_CALL(mockCertificateChain, getCerts()).WillRepeatedly(Return(std::vector<std::shared_ptr<const Certificate>>{cert1, cert2, cert3}));

    // when
    auto result = qve_get_collateral_dates(mockEnclaveIdentity, mockCertificateChain, &mockTcbInfo, &mockCollateral, &earliestIssueDate, &latestIssueDate, &earliestExpirationDate);

    // then
    EXPECT_EQ(result, SGX_QL_SUCCESS);
    EXPECT_EQ(earliestIssueDate, notBeforeEarliest);
    EXPECT_EQ(latestIssueDate, notBeforeLatest);
    EXPECT_EQ(earliestExpirationDate, notAfterEarliest);
}
