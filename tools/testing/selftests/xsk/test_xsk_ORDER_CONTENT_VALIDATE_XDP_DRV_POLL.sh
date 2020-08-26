#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

#Includes
. prereqs.sh

XSKDIR=xdpprogs
XSKOBJ=xdpxceiver
SPECFILE=veth.spec

VETH0=$(cat ${SPECFILE} | cut -d':' -f 1)
VETH1=$(cat ${SPECFILE} | cut -d':' -f 2 | cut -d',' -f 1)
NS1=$(cat ${SPECFILE} | cut -d':' -f 2 | cut -d',' -f 2)

vethXDPnative ${VETH0} ${VETH1} ${NS1}

./${XSKDIR}/${XSKOBJ} -i ${VETH0} -i ${VETH1},${NS1} -N -p -C 10000

retval=$?

test_exit $retval
