#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

. prereqs.sh
. xskenv.sh

TEST_NAME="XSK FRAMEWORK"

test_status $ksft_pass "${TEST_NAME}"

cleanup_exit ${VETH0} ${VETH1} ${NS1}

test_exit $retval 0
