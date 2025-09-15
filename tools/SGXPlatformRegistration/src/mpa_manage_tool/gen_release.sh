#!/usr/bin/env bash
#
# Copyright (C) 2011-2024 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR="${SCRIPT_DIR}/../../../"

SGX_VERSION=$(awk '/STRFILEVER/ {print $3}' ${ROOT_DIR}/QuoteGeneration/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')


rel_dir_base=mpa_manager_v$SGX_VERSION
rel_dir_name=$rel_dir_base$1

rm -rf $rel_dir_base*
make clean
make STANDALONE=1

mkdir $rel_dir_name
cp "${SCRIPT_DIR}/../build/bin/mpa_manage" $rel_dir_name
cp "${SCRIPT_DIR}/../build/lib64/libmpa_uefi.so" $rel_dir_name/libmpa_uefi.so.1
cp "${SCRIPT_DIR}/../config/mpa_registration.conf" $rel_dir_name
sed -i '/#proxy/d' "$rel_dir_name/mpa_registration.conf" # remove proxy-related configuration (unrelated to this tool)
sed -i '/#subscription/d' "$rel_dir_name/mpa_registration.conf" # remove subscription-key-related configuration (unrelated to this tool)
sed -i '/#uefi/d' "$rel_dir_name/mpa_registration.conf" # remove uefi path configuration
sed -i '/./,$!d'  "$rel_dir_name/mpa_registration.conf" #remove leading empty lines
# CONSIDER: Add standalone readme
cp "${SCRIPT_DIR}/../license.txt" $rel_dir_name  #TODO: Check license, BOM, ...

tar cvpzf $rel_dir_name.tar.gz $rel_dir_name

exit 0

