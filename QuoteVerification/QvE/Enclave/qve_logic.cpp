/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "qve_logic.h"


time_t getEarliestIssueDate(const CertificateChain* chain) {
    auto certs = chain->getCerts();
    auto comp_certs_issue_date = [](const std::shared_ptr<const Certificate> &ca, const std::shared_ptr<const Certificate> &cb) {
            return ca->getValidity().getNotBeforeTime() < cb->getValidity().getNotBeforeTime();
    };
    return (certs.empty()) ? time_t{0} : (*std::min_element(certs.begin(), certs.end(), comp_certs_issue_date))->getValidity().getNotBeforeTime();
}

time_t getLatestIssueDate(const CertificateChain* chain) {
    auto certs = chain->getCerts();
    auto comp_certs_issue_date = [](const std::shared_ptr<const Certificate> &ca, const std::shared_ptr<const Certificate> &cb) {
        return ca->getValidity().getNotBeforeTime() < cb->getValidity().getNotBeforeTime();
    };
    return (certs.empty()) ? time_t{0} : (*std::max_element(certs.begin(), certs.end(), comp_certs_issue_date))->getValidity().getNotBeforeTime();
}

time_t getEarliestExpirationDate(const CertificateChain* chain) {
    auto certs = chain->getCerts();
    auto comp_certs_exp_date = [](const std::shared_ptr<const Certificate> &ca, const std::shared_ptr<const Certificate> &cb) {
                return ca->getValidity().getNotAfterTime() < cb->getValidity().getNotAfterTime();
    };
    return (certs.empty()) ? time_t{0} : (*std::min_element(certs.begin(), certs.end(), comp_certs_exp_date))->getValidity().getNotAfterTime();
}

quote3_error_t qve_get_collateral_dates(const json::EnclaveIdentity &enclaveIdentity,
                                               CertificateChain &qe_identity_issuer_chain,
                                               const json::TcbInfo* p_tcb_info_obj,
                                               const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
                                               time_t* p_qe_iden_earliest_issue_date,
                                               time_t* p_qe_iden_latest_issue_date,
                                               time_t* p_qe_iden_earliest_expiration_date) {

    if (p_tcb_info_obj == NULL ||
        p_quote_collateral == NULL ||
        p_qe_iden_earliest_issue_date == NULL ||
        p_qe_iden_latest_issue_date == NULL ||
        p_qe_iden_earliest_expiration_date == NULL) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    *p_qe_iden_earliest_issue_date = 0;
    *p_qe_iden_latest_issue_date = 0;
    *p_qe_iden_earliest_expiration_date = 0;

    if (qe_identity_issuer_chain.parse((reinterpret_cast<const char*>(p_quote_collateral->qe_identity_issuer_chain))) != STATUS_OK)
        return SGX_QL_PCK_CERT_CHAIN_ERROR;

    //supports only EnclaveIdentity V2 and V3
    //
    uint32_t version = enclaveIdentity.getVersion();
    if (version != 2 && version != 3)
        return SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT;

    //supports only TCBInfo V2 and V3
    //
    version = p_tcb_info_obj->getVersion();
    if (version != 2 && version != 3)
        return SGX_QL_TCBINFO_UNSUPPORTED_FORMAT;

    *p_qe_iden_earliest_issue_date = getEarliestIssueDate(&qe_identity_issuer_chain);
    *p_qe_iden_latest_issue_date = getLatestIssueDate(&qe_identity_issuer_chain);
    *p_qe_iden_earliest_expiration_date = getEarliestExpirationDate(&qe_identity_issuer_chain);

    if (*p_qe_iden_earliest_issue_date == 0 || *p_qe_iden_latest_issue_date == 0 || *p_qe_iden_earliest_expiration_date == 0)
        return SGX_QL_ERROR_UNEXPECTED;

    return SGX_QL_SUCCESS;
}

quote3_error_t deserializeVerCollatInfo(const std::vector<uint8_t> &bytes, verification_collateral_info_t &info) {
    if (bytes.empty() ||
        bytes.size() < offsetof(verification_collateral_info_t, sa_list) ||
        bytes.size() > (offsetof(verification_collateral_info_t, sa_list) + MAX_SA_LIST_SIZE))
        return SGX_QL_ERROR_INVALID_PARAMETER;

    using Data = verification_collateral_info_t;

    info.id = parseBytesLE<decltype(Data::id)>(bytes.data());
    size_t offset = sizeof(Data::id);

    info.version = parseBytesLE<decltype(Data::version)>(bytes.data(), offset);
    offset += sizeof(Data::version);

    info.issue_date_min = parseBytesLE<decltype(Data::issue_date_min)>(bytes.data(), offset);
    offset += sizeof(Data::issue_date_min);

    info.issue_date_max = parseBytesLE<decltype(Data::issue_date_max)>(bytes.data(), offset);
    offset += sizeof(Data::issue_date_max);

    info.expiration_date_min = parseBytesLE<decltype(Data::expiration_date_min)>(bytes.data(), offset);
    offset += sizeof(Data::expiration_date_min);

    info.tcb_eval_data_num = parseBytesLE<decltype(Data::tcb_eval_data_num)>(bytes.data(), offset);
    offset += sizeof(Data::tcb_eval_data_num);

    info.tcb_date_min = parseBytesLE<decltype(Data::tcb_date_min)>(bytes.data(), offset);
    offset += sizeof(Data::tcb_date_min);

    for (size_t i = offset, j = 0; i < bytes.size(); ++i, ++j)
        info.sa_list[j] = static_cast<char>(bytes[i]);

    return SGX_QL_SUCCESS;
}
