/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _QVE_UTILS_H
#define _QVE_UTILS_H

#include <climits>
#include <map>

#include "CertVerification/CertificateChain.h"
#include "SgxEcdsaAttestation/QuoteVerification.h"
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "QuoteVerification/Quote.h"
#include "sgx_qve_header.h"
#include "sgx_ql_lib_common.h"


using namespace intel::sgx::dcap::parser;
using namespace intel::sgx::dcap::parser::x509;
using namespace intel::sgx::dcap::parser::json;


#pragma pack(push, 1) // Set alignment to 1 byte
struct verification_collateral_info_t
{
    // header
    int16_t id {0};
    int16_t version {0};

    // data
    time_t issue_date_min {0};
    time_t issue_date_max {0};
    time_t expiration_date_min {0};

    uint32_t tcb_eval_data_num {0};
    time_t tcb_date_min {0};

    char sa_list[MAX_SA_LIST_SIZE] = {0};
};
#pragma pack(pop) // Restore default alignment

template
<
    typename T,
    typename std::enable_if<std::is_integral<T>::value, int>::type = 0
>
T parseBytesLE(const uint8_t *raw, size_t offset = 0)
{
    static_assert(CHAR_BIT == 8, "Requires 8 bit byte");

    static constexpr size_t SIZE = sizeof(T);

    T ret{0};
    for(size_t i = offset, pos = SIZE - 1; i < offset + SIZE; ++i, --pos)
    {
        const size_t op = (SIZE - 1 - pos) * 8;
        ret |= static_cast<T>(raw[i]) << op;
    }

    return ret;
}

/**
 * Check if a given status code is an expiration error or not.
 *
 * @param status_err[IN] - Status error code.
 *
 * @return 1: Status indicates an expiration error.
 * @return 0: Status indicates error other than expiration error.
*
 **/
inline bool is_nonterminal_error(Status status_err) {
    auto nonterminal_errors = {
        STATUS_TCB_OUT_OF_DATE,
        STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED,
        STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE,
        STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE,
        STATUS_QE_IDENTITY_OUT_OF_DATE,
        STATUS_SGX_TCB_INFO_EXPIRED,
        STATUS_SGX_PCK_CERT_CHAIN_EXPIRED,
        STATUS_SGX_CRL_EXPIRED,
        STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED,
        STATUS_SGX_ENCLAVE_IDENTITY_EXPIRED,
        STATUS_TCB_CONFIGURATION_NEEDED,
        STATUS_TCB_SW_HARDENING_NEEDED,
        STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED,
        STATUS_TCB_TD_RELAUNCH_ADVISED,
        STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED
    };

    return std::find(nonterminal_errors.begin(), nonterminal_errors.end(), status_err) != nonterminal_errors.end();
}

/**
 * Check if a given status code is an expiration error or not.
 *
 * @param status_err[IN] - Status error code.
 *
 * @return 1: Status indicates an expiration error.
 * @return 0: Status indicates error other than expiration error.
*
 **/
inline bool is_expiration_error(Status status_err) {
    auto expiration_errors = {
        STATUS_SGX_TCB_INFO_EXPIRED,
        STATUS_SGX_PCK_CERT_CHAIN_EXPIRED,
        STATUS_SGX_CRL_EXPIRED,
        STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED,
        STATUS_SGX_ENCLAVE_IDENTITY_EXPIRED
    };
    return std::find(expiration_errors.begin(), expiration_errors.end(), status_err) != expiration_errors.end();
}

inline sgx_ql_qv_result_t status_error_to_ql_qve_result(TcbStatus status) {
    const std::map<TcbStatus, sgx_ql_qv_result_t> translation_map = {
            {TcbStatus::UpToDate, SGX_QL_QV_RESULT_OK},
            {TcbStatus::Revoked, SGX_QL_QV_RESULT_REVOKED},
            {TcbStatus::OutOfDate, SGX_QL_QV_RESULT_OUT_OF_DATE},
            {TcbStatus::OutOfDateConfigurationNeeded, SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED},
            {TcbStatus::ConfigurationNeeded, SGX_QL_QV_RESULT_CONFIG_NEEDED}
    };
    auto ret_it = translation_map.find(status);
    return ret_it != translation_map.end() ? ret_it->second : SGX_QL_QV_RESULT_UNSPECIFIED;
}

/**
 * Helper function to return earliest & latest issue date and expiration date comparing all collaterals.
 * @param p_cert_chain_obj[IN] - Pointer to CertificateChain object containing PCK Cert chain (for quote with cert type 5, this should be extracted from the quote).
 * @param p_tcb_info_obj[IN] - Pointer to TcbInfo object.
 * @param p_quote_collateral[IN] - Pointer to _sgx_ql_qve_collateral_t struct.
 * @param p_earliest_issue_date[OUT] - Pointer to store the value of the earliest issue date of all input data in quote verification collaterals.
 * @param p_earliest_expiration_date[OUT] - Pointer to store the value of the earliest expiration date of all collaterals used in quote verification collaterals.
 * @param p_latest_issue_date[OUT] - Pointer to store the value of the latest issue date of all input data in quote verification collaterals.
 * @param p_latest_expiration_date[OUT] - Pointer to store the value of the latest expiration date of all collaterals used in quote verification collaterals.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_ATT_KEY_CERT_DATA_INVALID
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t qve_get_collateral_dates(const json::EnclaveIdentity &enclaveIdentity,
                                               CertificateChain &qe_identity_issuer_chain,
                                               const json::TcbInfo* p_tcb_info_obj,
                                               const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
                                               time_t* p_qe_iden_earliest_issue_date,
                                               time_t* p_qe_iden_latest_issue_date,
                                               time_t* p_qe_iden_earliest_expiration_date);


time_t getEarliestIssueDate(const CertificateChain* chain);
time_t getLatestIssueDate(const CertificateChain* chain);
time_t getEarliestExpirationDate(const CertificateChain* chain);

quote3_error_t deserializeVerCollatInfo(const std::vector<uint8_t> &bytes, verification_collateral_info_t &info);

#endif //_QVE_UTILS_H
