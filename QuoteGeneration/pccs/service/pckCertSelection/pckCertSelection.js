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

import X509 from '../x509/x509.js';
import PckCertificate from './PckCertificate.js';
import Tcb from './Tcb.js';
import util from "util";
import Constants from '../constants/index.js';
import PccsError from '../utils/PccsError.js';

export function selectBestPckCert(rawCpusvn, rawPcesvn, pceid, pckCertData, tcbInfo) {
    let pckCerts = parsePckCerts(pckCertData);
    validateInput(pceid, pckCerts, tcbInfo);

    // create structure for collecting PCK certs that match TCB level
    let tcbPckCertsBuckets = createBucketsForCertificatesByTcb(tcbInfo);
    // match pck certs to proper pckCertSelection info
    pckCerts.forEach(pckCert => {
        for (const tcbBucket of tcbPckCertsBuckets) {
            try {
                if (pckCert.tcb.compare(tcbBucket.tcb) >= 0) { // pck cert is greater or equal
                    tcbBucket.certs.push(pckCert);
                    break;
                }
            } catch (e) {
                if (e instanceof PccsError) { // error is a result of invalid cert (incomparable TCB) - ignoring cert
                    break;
                } else {
                    throw e;
                }
            }
        }
        // if cert does not match any TCB level it is not valid - omit
    });

    // counting equivalent for platform TCB based on TCB info
    const rawTCB = new Tcb(rawCpusvn, littleEndianHexStringToInteger(rawPcesvn));
    const eqvTCB = rawTCB.computeEquivalent(tcbPckCertsBuckets)
    if (!eqvTCB) {
        throw new Error(util.format('No equivalent TCB found for given raw TCB: CPUSVN %s, PCESVN: %s', rawCpusvn, rawPcesvn));
    }

    // looking for the best pck cert in bucket
    return selectBestPckCertFromTcbBucket(rawTCB, eqvTCB.certs);
}

function selectBestPckCertFromTcbBucket(rawTCB, pckCerts) {
    pckCerts.sort((x,y) => y.tcb.compare(x.tcb));
    const bestPckCert = pckCerts.find(pckCert => rawTCB.compare(pckCert.tcb) >= 0).pckCertFromDb;
    if (bestPckCert === undefined) {
        throw new Error('No certificate found for given platform');
    }
    return bestPckCert;
}

function parsePckCerts(pckCertData) {
    let parsedPckCerts = [];
    pckCertData.forEach(pckCertDataItem => {
        const x509 = new X509();
        if (!x509.parseCert(pckCertDataItem.pck_cert)) {
            throw new Error('Parsing PCK certificate from DB failed')
        }
        parsedPckCerts.push(new PckCertificate(pckCertDataItem, x509, new Tcb(x509.cpusvn, x509.pcesvn)));
    });
    return parsedPckCerts;
}

function validateInput(pceId, pckCerts, tcbInfo) {
    // check if PCEID is the same for platform and TCB Info
    if (tcbInfo.pceId.toUpperCase() !== pceId.toUpperCase()) {
        throw new Error(util.format('PCEID in TCB Info (%s) is different than platform PCEID (%s)', tcbInfo.pceId, pceId));
    }

    let ppid;
    pckCerts.forEach(pckCert => {
        if (pckCert.x509.version !== Constants.PCK_CERT_VERSION) {
            throw new Error(util.format('PCK certificate version (%s) is different than expected version (%s)', pckCert.x509.version, Constants.PCK_CERT_VERSION));
        }

        // check if PCEID in cert matches the platform PCEID
        if (pckCert.x509.pceId !== pceId.toUpperCase()) {
            throw new Error(util.format('PCEID in cert (%s) is different than platform PCEID (%s)', pckCert.x509.pceId, pceId));
        }
        // check if FMSPC in cert matches the one in TCB info
        if (pckCert.x509.fmspc !== tcbInfo.fmspc.toUpperCase()) {
            throw new Error(util.format('FMSPC in cert (%s) is different than in TCB info (%s)', pckCert.x509.fmspc, tcbInfo.fmspc));
        }
        // check if ppid is the same in every cert
        if (ppid === undefined) {
            ppid = pckCert.x509.ppid;
        } else if (pckCert.x509.ppid !== ppid) {
            throw new Error('PPIDs are not the same in every PCK certificate')
        }
    });
}

function createBucketsForCertificatesByTcb(tcbInfo) {
    // creating bucket for each pckCertSelection level to collect pck certs
    const tcbPckCertsBuckets = tcbInfo.tcbLevels.map(tcbLevel => {
        let cpusvn = [];
        tcbLevel.tcb.sgxtcbcomponents.forEach(component => cpusvn.push(component.svn.toString(16).toUpperCase().padStart(2,'0')));
        return { tcb: new Tcb(cpusvn.join(''), tcbLevel.tcb.pcesvn), certs: [] };
    });
    // sort tcbinfo (in case it wasn't sorted)
    tcbPckCertsBuckets.sort((x,y) => y.tcb.compare(x.tcb));
    return tcbPckCertsBuckets;
}

function littleEndianHexStringToInteger(leHexString) {
    let beHexString = leHexString.match(/.{2}/g).reverse().join('');
    return parseInt(beHexString, 16);
}