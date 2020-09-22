#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

. prereqs.sh
. xskenv.sh

TEST_NAME="SKB NOPOLL TEARDOWN"

vethXDPgeneric ${VETH0} ${VETH1} ${NS1}

./${XSKDIR}/${XSKOBJ} -i ${VETH0} -i ${VETH1},${NS1} -S -T -C ${NUMPKTS}

retval=$?
test_status $retval "${TEST_NAME}"

test_exit $retval 0
