# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

VAR_CFLAGS :=
VAR_LDLIBS :=
ifeq ($(VAR_LDLIBS),)
VAR_LDLIBS :=
endif

CFLAGS += -O2 -g -std=gnu99 -Wall -I../../../../usr/include/ $(VAR_CFLAGS)
LDLIBS += $(VAR_LDLIBS)

XSKDIR := $(realpath ./xdpprogs)
XSKOBJ := xdpxceiver

TEST_PROGS := test_xsk_ORDER_CONTENT_VALIDATE_XDP_SKB.sh \
			  test_xsk_ORDER_CONTENT_VALIDATE_XDP_DRV.sh \
			  test_xsk_ORDER_CONTENT_VALIDATE_XDP_SKB_POLL.sh \
			  test_xsk_ORDER_CONTENT_VALIDATE_XDP_DRV_POLL.sh \
			  test_xsk_ORDER_CONTENT_VALIDATE_XDP_SKB_BIDI.sh \
			  test_xsk_ORDER_CONTENT_VALIDATE_XDP_DRV_BIDI.sh \
			  test_xsk_ORDER_CONTENT_VALIDATE_XDP_SKB_TEARDOWN.sh \
			  test_xsk_ORDER_CONTENT_VALIDATE_XDP_DRV_TEARDOWN.sh
TEST_FILES := prereqs.sh
TEST_TRANSIENT_FILES := veth.spec
TEST_PROGS_EXTENDED := $(XSKDIR)/$(XSKOBJ)

.PHONY: INITSCRIPT

INITSCRIPT:
	./init_veth.sh

PREREQS: INITSCRIPT

all: $(TEST_PROGS_EXTENDED) PREREQS

KSFT_KHDR_INSTALL := 1
include ../lib.mk

$(TEST_PROGS_EXTENDED): $(XSKDIR)/$(XSKOBJ)

$(XSKDIR)/$(XSKOBJ):
	cd $(XSKDIR) && $(MAKE)

override define CLEAN
	$(RM) $(TEST_TRANSIENT_FILES)
	cd $(XSKDIR) && $(MAKE) clean
endef
