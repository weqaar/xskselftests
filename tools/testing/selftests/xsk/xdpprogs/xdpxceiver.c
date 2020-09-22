// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 Intel Corporation. */

/*
 * Some functions in this program are taken from
 * Linux kernel samples/bpf/xdpsock* and modified
 * for use.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <asm/barrier.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <stdatomic.h>

#include <bpf/xsk.h>
#include "xdpxceiver.h"
#include "../../kselftest.h"

static void __exit_with_error(int error, const char *file, const char *func, int line)
{
	ksft_test_result_fail
		("[%s:%s:%i]: ERROR: %d/\"%s\"\n", file, func, line, error, strerror(error));
	ksft_exit_xfail();
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static void pthread_init_mutex(void)
{
	pthread_mutex_init(&syncmutex, NULL);
	pthread_mutex_init(&syncmutextx, NULL);
	pthread_mutex_init(&syncmutexrx, NULL);
	pthread_cond_init(&signalrxcondition, NULL);
	pthread_cond_init(&signaltxcondition, NULL);
}

static void pthread_destroy_mutex(void)
{
	pthread_mutex_destroy(&syncmutex);
	pthread_mutex_destroy(&syncmutextx);
	pthread_mutex_destroy(&syncmutexrx);
	pthread_cond_destroy(&signalrxcondition);
	pthread_cond_destroy(&signaltxcondition);
}

static void *memset32_htonl(void *dest, u32 val, u32 size)
{
	u32 *ptr = (u32 *)dest;
	int i;

	val = htonl(val);

	for (i = 0; i < (size & (~0x3)); i += 4)
		ptr[i >> 2] = val;

	for (; i < size; i++)
		((char *)dest)[i] = ((char *)&val)[i & 3];

	return dest;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (__force u32)csum;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__force __sum16)~sum;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline u32 from64to32(u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (u32)x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len, __u8 proto, __wsum sum);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (__force u32)sum;

	s += (__force u32)saddr;
	s += (__force u32)daddr;
#ifdef __BIG_ENDIAN__
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return (__force __wsum)from64to32(s);
}

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len, __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline u16 udp_csum(u32 saddr, u32 daddr, u32 len, u8 proto, u16 *udp_pkt)
{
	u32 csum = 0;
	u32 cnt = 0;

	/* udp hdr and data */
	for (; cnt < len; cnt += 2)
		csum += udp_pkt[cnt >> 1];

	return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

static void gen_eth_hdr(void *data, struct ethhdr *eth_hdr)
{
	memcpy(eth_hdr->h_dest, ((struct ifobjectstruct *)data)->dst_mac, ETH_ALEN);
	memcpy(eth_hdr->h_source, ((struct ifobjectstruct *)data)->src_mac, ETH_ALEN);
	eth_hdr->h_proto = htons(ETH_P_IP);
}

static void gen_ip_hdr(void *data, struct iphdr *ip_hdr)
{
	ip_hdr->version = IPVERSION;
	ip_hdr->ihl = 0x5;
	ip_hdr->tos = 0x0;
	ip_hdr->tot_len = htons(IP_PKT_SIZE);
	ip_hdr->id = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = IPDEFTTL;
	ip_hdr->protocol = IPPROTO_UDP;
	ip_hdr->saddr = ((struct ifobjectstruct *)data)->src_ip;
	ip_hdr->daddr = ((struct ifobjectstruct *)data)->dst_ip;
	ip_hdr->check = 0;
}

static void gen_udp_hdr(void *data, void *arg, struct udphdr *udp_hdr)
{
	udp_hdr->source = htons(((struct ifobjectstruct *)arg)->src_port);
	udp_hdr->dest = htons(((struct ifobjectstruct *)arg)->dst_port);
	udp_hdr->len = htons(UDP_PKT_SIZE);
	memset32_htonl(pkt_data + PKT_HDR_SIZE,
		       htonl(((struct generic_data *)data)->seqnum), UDP_PKT_DATA_SIZE);
}

static void gen_udp_csum(struct udphdr *udp_hdr, struct iphdr *ip_hdr)
{
	udp_hdr->check = 0;
	udp_hdr->check =
	    udp_csum(ip_hdr->saddr, ip_hdr->daddr, UDP_PKT_SIZE, IPPROTO_UDP, (u16 *)udp_hdr);
}

static void gen_eth_frame(struct xsk_umem_info *umem, u64 addr)
{
	memcpy(xsk_umem__get_data(umem->buffer, addr), pkt_data, PKT_SIZE);
}

static void xsk_configure_umem(struct ifobjectstruct *data, void *buffer, u64 size)
{
	struct xsk_umem_config cfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = opt_xsk_frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = opt_umem_flags
	};
	int ret;

	data->umem = calloc(1, sizeof(struct xsk_umem_info));
	if (!data->umem)
		exit_with_error(errno);

	ret = xsk_umem__create(&data->umem->umem, buffer, size,
			       &data->umem->fq, &data->umem->cq, &cfg);
	if (ret)
		exit_with_error(ret);

	data->umem->buffer = buffer;
}

static void xsk_populate_fill_ring(struct xsk_umem_info *umem)
{
	int ret, i;
	u32 idx;

	ret = xsk_ring_prod__reserve(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		exit_with_error(ret);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * opt_xsk_frame_size;
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
}

static int xsk_configure_socket(struct ifobjectstruct *ifobject)
{
	struct xsk_socket_config cfg;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	ifobject->xsk = calloc(1, sizeof(struct xsk_socket_info));
	if (!ifobject->xsk)
		exit_with_error(errno);

	ifobject->xsk->umem = ifobject->umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;

	rxr = (ifobject->fv.vector == rx) ? &ifobject->xsk->rx : NULL;
	txr = (ifobject->fv.vector == tx) ? &ifobject->xsk->tx : NULL;

	ret = xsk_socket__create(&ifobject->xsk->xsk, ifobject->opt_if,
				 opt_queue, ifobject->umem->umem, rxr, txr, &cfg);

	if (ret)
		return 1;

	return 0;
}

static struct option long_options[] = {
	{"interface", required_argument, 0, 'i'},
	{"queue", optional_argument, 0, 'q'},
	{"poll", no_argument, 0, 'p'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{"copy", no_argument, 0, 'c'},
	{"debug", optional_argument, 0, 'D'},
	{"tx-pkt-count", optional_argument, 0, 'C'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
	    "  Usage: %s [OPTIONS]\n"
	    "  Options:\n"
	    "  -i, --interface      Use interface\n"
	    "  -q, --queue=n        Use queue n (default 0)\n"
	    "  -p, --poll           Use poll syscall\n"
	    "  -S, --xdp-skb=n      Use XDP SKB mode\n"
	    "  -N, --xdp-native=n   Enforce XDP DRV (native) mode\n"
	    "  -c, --copy           Force copy mode\n"
	    "  -D, --debug          Debug mode - dump packets L2 - L5\n"
	    "  -C, --tx-pkt-count=n Number of packets to send\n";
	ksft_print_msg(str, prog);
}

static bool switch_namespace(int idx)
{
	char fqns[26] = "/var/run/netns/";
	int nsfd;

	strncat(fqns, ifdict[idx]->opt_ns, sizeof(fqns) - strlen(fqns) - 1);
	nsfd = open(fqns, O_RDONLY);

	if (nsfd == -1)
		exit_with_error(errno);

	if (setns(nsfd, 0) == -1)
		exit_with_error(errno);

	return true;
};

static void *nsswitchthread(void *args)
{
	if (switch_namespace(((struct targs *)args)->idx)) {
		ifdict[((struct targs *)args)->idx]->opt_ifindex =
		    if_nametoindex(ifdict[((struct targs *)args)->idx]->opt_if);
		if (!ifdict[((struct targs *)args)->idx]->opt_ifindex) {
			ksft_test_result_fail
				("ERROR: [%s] interface \"%s\" does not exist\n",
				 __func__, ifdict[((struct targs *)args)->idx]->opt_if);
			((struct targs *)args)->retptr = false;
		} else {
			ksft_print_msg("Interface found: %s\n",
				       ifdict[((struct targs *)args)->idx]->opt_if);
			((struct targs *)args)->retptr = true;
		}
	} else {
		((struct targs *)args)->retptr = false;
	}
	pthread_exit(NULL);
}

static int validate_interfaces(void)
{
	bool ret = true;

	for (int i = 0; i < MAX_INTERFACES; i++) {
		if (!strcmp(ifdict[i]->opt_if, "")) {
			ret = false;
			ksft_test_result_fail("ERROR: interfaces: -i <int>,<ns> -i <int>,<ns>.");
		}
		if (strcmp(ifdict[i]->opt_ns, "")) {
			struct targs *targs;

			targs = (struct targs *)malloc(sizeof(struct targs));
			if (!targs)
				exit_with_error(errno);

			targs->idx = i;
			if (pthread_create(&nsthread, NULL, nsswitchthread, (void *)targs))
				exit_with_error(errno);

			pthread_join(nsthread, NULL);

			if (targs->retptr)
				ksft_print_msg("NS switched: %s\n", ifdict[i]->opt_ns);

			free(targs);
		} else {
			ifdict[i]->opt_ifindex = if_nametoindex(ifdict[i]->opt_if);
			if (!ifdict[i]->opt_ifindex) {
				ksft_test_result_fail
					("ERROR: interface \"%s\" does not exist\n",
					 ifdict[i]->opt_if);
				ret = false;
			} else {
				ksft_print_msg("Interface found: %s\n", ifdict[i]->opt_if);
			}
		}
	}
	return ret;
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, interface_index = 0, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "i:q:pSNcDC:", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'i':
			if (interface_index == MAX_INTERFACES)
				break;
			char *sptr, *token;

			memcpy(ifdict[interface_index]->opt_if,
			       strtok_r(optarg, ",", &sptr), MAX_INTERFACE_NAME_CHARS);
			token = strtok_r(NULL, ",", &sptr);
			if (token)
				memcpy(ifdict[interface_index]->opt_ns, token,
				       MAX_INTERFACES_NAMESPACE_CHARS);
			interface_index++;
			break;
		case 'q':
			opt_queue = atoi(optarg);
			break;
		case 'p':
			opt_poll = 1;
			break;
		case 'S':
			opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
			opt_xdp_bind_flags |= XDP_COPY;
			UUT = ORDER_CONTENT_VALIDATE_XDP_SKB;
			break;
		case 'N':
			opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
			opt_xdp_bind_flags |= XDP_COPY;
			UUT = ORDER_CONTENT_VALIDATE_XDP_DRV;
			break;
		case 'c':
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'D':
			DEBUG_PKTDUMP = 1;
			break;
		case 'C':
			opt_pkt_count = atoi(optarg);
			break;
		default:
			usage(basename(argv[0]));
			ksft_exit_xfail();
		}
	}

	if (!validate_interfaces()) {
		usage(basename(argv[0]));
		ksft_exit_xfail();
	}
}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;

	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY || errno == ENETDOWN)
		return;
	exit_with_error(errno);
}

static inline void complete_tx_only(struct xsk_socket_info *xsk, int batch_size)
{
	unsigned int rcvd;
	u32 idx;

	if (!xsk->outstanding_tx)
		return;

	if (!opt_need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx))
		kick_tx(xsk);

	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, batch_size, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
		xsk->tx_npkts += rcvd;
	}
}

static void rx_pkt(struct xsk_socket_info *xsk, struct pollfd *fds)
{
	unsigned int rcvd, i;
	u32 idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	if (!rcvd) {
		if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq))
			ret = poll(fds, num_socks, opt_timeout);
		return;
	}

	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq))
			ret = poll(fds, num_socks, opt_timeout);
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	}

	pthread_mutex_lock(&syncmutexrx);
	for (i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		(void)xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		u64 orig = xsk_umem__extract_addr(addr);

		addr = xsk_umem__add_offset_to_addr(addr);
		pktnoderx = malloc(sizeof(struct pkt) + PKT_SIZE);
		if (!pktnoderx)
			exit_with_error(errno);

		pktnoderx->pktframe = (char *)malloc(PKT_SIZE);
		if (!pktnoderx->pktframe)
			exit_with_error(errno);

		memcpy(pktnoderx->pktframe, xsk_umem__get_data(xsk->umem->buffer, addr), PKT_SIZE);

		TAILQ_INSERT_HEAD(&head, pktnoderx, pktnodes);

		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = orig;
	}
	pthread_mutex_unlock(&syncmutexrx);

	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->rx_npkts += rcvd;
}

static void tx_only(struct xsk_socket_info *xsk, u32 *frameptr, int batch_size)
{
	u32 idx;
	unsigned int i;

	while (xsk_ring_prod__reserve(&xsk->tx, batch_size, &idx) < batch_size)
		complete_tx_only(xsk, batch_size);

	for (i = 0; i < batch_size; i++) {
		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx + i);

		tx_desc->addr = (*frameptr + i) << XSK_UMEM__DEFAULT_FRAME_SHIFT;
		tx_desc->len = PKT_SIZE;
	}

	xsk_ring_prod__submit(&xsk->tx, batch_size);
	xsk->outstanding_tx += batch_size;
	*frameptr += batch_size;
	*frameptr %= NUM_FRAMES;
	complete_tx_only(xsk, batch_size);
}

static inline int get_batch_size(int pkt_cnt)
{
	if (!opt_pkt_count)
		return opt_batch_size;

	if (pkt_cnt + opt_batch_size <= opt_pkt_count)
		return opt_batch_size;

	return opt_pkt_count - pkt_cnt;
}

static void complete_tx_only_all(void *arg)
{
	bool pending;
	int i;

	do {
		pending = false;
		for (i = 0; i < num_socks; i++) {
			if (((struct ifobjectstruct *)arg)->xsk->outstanding_tx) {
				complete_tx_only(((struct ifobjectstruct *)
						  arg)->xsk, opt_batch_size);
				pending = !!((struct ifobjectstruct *)arg)->xsk->outstanding_tx;
			}
		}
	} while (pending);
}

static void tx_only_all(void *arg)
{
	struct pollfd fds[MAX_SOCKS] = {};
	u32 frame_nb = 0;
	int pkt_cnt = 0;
	int i, ret;

	for (i = 0; i < num_socks; i++) {
		fds[i].fd = xsk_socket__fd(((struct ifobjectstruct *)arg)->xsk->xsk);
		fds[i].events = POLLOUT;
	}

	while ((opt_pkt_count && pkt_cnt < opt_pkt_count) || !opt_pkt_count) {
		int batch_size = get_batch_size(pkt_cnt);

		if (opt_poll) {
			ret = poll(fds, num_socks, opt_timeout);
			if (ret <= 0)
				continue;

			if (!(fds[0].revents & POLLOUT))
				continue;
		}

		tx_only(((struct ifobjectstruct *)arg)->xsk, &frame_nb, batch_size);

		pkt_cnt += batch_size;
	}

	if (opt_pkt_count)
		complete_tx_only_all(arg);
}

static void worker_pkt_dump(void)
{
	struct in_addr ipaddr;

	fprintf(stdout, "---------------------------------------\n");
	for (int iter = 0; iter < NUM_FRAMES - 1; iter++) {
		/*extract L2 frame */
		fprintf(stdout, "DEBUG>> L2: dst mac: ");
		for (int i = 0; i < ETH_ALEN; i++)
			fprintf(stdout, "%02X", ((struct ethhdr *)
						pktbuf[iter]->payload)->h_dest[i]);

		fprintf(stdout, "\nDEBUG>> L2: src mac: ");
		for (int i = 0; i < ETH_ALEN; i++)
			fprintf(stdout, "%02X", ((struct ethhdr *)
						pktbuf[iter]->payload)->h_source[i]);

		/*extract L3 frame */
		fprintf(stdout, "\nDEBUG>> L3: ip_hdr->ihl: %02X\n",
			((struct iphdr *)(pktbuf[iter]->payload + sizeof(struct ethhdr)))->ihl);

		ipaddr.s_addr =
		    ((struct iphdr *)(pktbuf[iter]->payload + sizeof(struct ethhdr)))->saddr;
		fprintf(stdout, "DEBUG>> L3: ip_hdr->saddr: %s\n", inet_ntoa(ipaddr));

		ipaddr.s_addr =
		    ((struct iphdr *)(pktbuf[iter]->payload + sizeof(struct ethhdr)))->daddr;
		fprintf(stdout, "DEBUG>> L3: ip_hdr->daddr: %s\n", inet_ntoa(ipaddr));

		/*extract L4 frame */
		fprintf(stdout, "DEBUG>> L4: udp_hdr->src: %d\n",
			ntohs(((struct udphdr *)(pktbuf[iter]->payload +
						 sizeof(struct ethhdr) +
						 sizeof(struct iphdr)))->source));

		fprintf(stdout, "DEBUG>> L4: udp_hdr->dst: %d\n",
			ntohs(((struct udphdr *)(pktbuf[iter]->payload +
						 sizeof(struct ethhdr) +
						 sizeof(struct iphdr)))->dest));
		/*extract L5 frame */
		int payload = *((uint32_t *)(pktbuf[iter]->payload + PKT_HDR_SIZE));

		if (payload == EOT) {
			ksft_print_msg("End-of-tranmission frame received\n");
			fprintf(stdout, "---------------------------------------\n");
			break;
		}
		fprintf(stdout, "DEBUG>> L5: payload: %d\n", payload);
		fprintf(stdout, "---------------------------------------\n");
	}
}

static void *worker_pkt_validate(void *arg)
{
	u32 payloadseqnum = -2;

	pthread_mutex_lock(&syncmutexrx);

	while (1) {
		pktnoderxq = malloc(sizeof(struct pkt));
		pktnoderxq = TAILQ_LAST(&head, head_s);
		if (!pktnoderxq)
			break;

		payloadseqnum = *((uint32_t *)(pktnoderxq->pktframe + PKT_HDR_SIZE));
		if (DEBUG_PKTDUMP && payloadseqnum != EOT) {
			pktobj = (struct pktframe *)malloc(sizeof(struct pktframe));
			pktobj->payload = (char *)malloc(PKT_SIZE);
			memcpy(pktobj->payload, pktnoderxq->pktframe, PKT_SIZE);
			pktbuf[payloadseqnum] = pktobj;
		}

		if (payloadseqnum == EOT) {
			ksft_print_msg("End-of-tranmission frame received: PASS\n");
			sigvar = 1;
			break;
		}

		if (prevpkt + 1 != payloadseqnum) {
			ksft_test_result_fail
				("ERROR: [%s] prevpkt [%d], payloadseqnum [%d]\n",
				 __func__, prevpkt, payloadseqnum);
			ksft_exit_xfail();
		}

		TAILQ_REMOVE(&head, pktnoderxq, pktnodes);
		free(pktnoderxq->pktframe);
		free(pktnoderxq);
		pktnoderxq = NULL;
		prevpkt = payloadseqnum;
		pktcounter++;
	}
	pthread_mutex_unlock(&syncmutexrx);
	pthread_exit(NULL);
}

static void *worker_testapp_validate(void *arg)
{
	void *bufs;
	int ret, ctr = 0;
	struct generic_data *data = (struct generic_data *)malloc(sizeof(struct generic_data));
	struct ethhdr *eth_hdr = (struct ethhdr *)pkt_data;
	struct iphdr *ip_hdr = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	struct udphdr *udp_hdr =
	    (struct udphdr *)(pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));

	pthread_attr_setstacksize(&attr, THREAD_STACK);

	bufs = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
		    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
	if (bufs == MAP_FAILED)
		exit_with_error(errno);

	if (strcmp(((struct ifobjectstruct *)arg)->opt_ns, ""))
		switch_namespace(((struct ifobjectstruct *)arg)->ifdict_index);

	if (((struct ifobjectstruct *)arg)->fv.vector == tx) {
		xsk_configure_umem((struct ifobjectstruct *)arg, bufs,
				   NUM_FRAMES * opt_xsk_frame_size);
		ret = xsk_configure_socket((struct ifobjectstruct *)arg);

		/* Retry Create Socket if it fails as xsk_socket__create()
		 * is asynchronous
		 *
		 * Essential to lock Mutex here to prevent Tx thread from
		 * entering before Rx and causing a deadlock
		 */
		pthread_mutex_lock(&syncmutextx);
		while (ret && (ctr < SOCK_RECONF_CTR)) {
			atomic_store(&spinningtx, 1);
			xsk_configure_umem((struct ifobjectstruct *)arg,
					   bufs, NUM_FRAMES * opt_xsk_frame_size);
			ret = xsk_configure_socket((struct ifobjectstruct *)arg);
			usleep(USLEEP_MAX);
			ctr++;
		}
		atomic_store(&spinningtx, 0);
		pthread_mutex_unlock(&syncmutextx);

		if (ctr >= SOCK_RECONF_CTR)
			exit_with_error(ret);

		int spinningrxctr = 0;

		while ((atomic_load(&spinningrx)) && (spinningrxctr < SOCK_RECONF_CTR)) {
			spinningrxctr++;
			usleep(USLEEP_MAX);
		}

		ksft_print_msg("Interface [%s] vector [Tx]\n",
			       ((struct ifobjectstruct *)arg)->opt_if);
		for (int i = 0; i < NUM_FRAMES; i++) {
			/*send EOT frame */
			if (i == (NUM_FRAMES - 1))
				data->seqnum = -1;
			else
				data->seqnum = i;
			gen_udp_hdr((void *)data, (void *)arg, udp_hdr);
			gen_ip_hdr((void *)arg, ip_hdr);
			gen_udp_csum(udp_hdr, ip_hdr);
			gen_eth_hdr((void *)arg, eth_hdr);
			gen_eth_frame(((struct ifobjectstruct *)arg)->umem, i * opt_xsk_frame_size);
		}

		free(data);

		ksft_print_msg("Sending %d packets on interface %s\n",
			       (opt_pkt_count - 1), ((struct ifobjectstruct *)arg)->opt_if);
		tx_only_all(arg);
	} else if (((struct ifobjectstruct *)arg)->fv.vector == rx) {
		xsk_configure_umem((struct ifobjectstruct *)arg, bufs,
				   NUM_FRAMES * opt_xsk_frame_size);

		ret = xsk_configure_socket((struct ifobjectstruct *)arg);

		/* Retry Create Socket if it fails as xsk_socket__create() is
		 * asynchronous
		 *
		 * Essential to lock Mutex here to prevent Tx thread from entering
		 * before Rx and causing a deadlock
		 */
		pthread_mutex_lock(&syncmutextx);
		while (ret && (ctr < SOCK_RECONF_CTR)) {
			atomic_store(&spinningrx, 1);
			xsk_configure_umem((struct ifobjectstruct *)arg,
					   bufs, NUM_FRAMES * opt_xsk_frame_size);
			ret = xsk_configure_socket((struct ifobjectstruct *)arg);
			usleep(USLEEP_MAX);
			ctr++;
		}
		atomic_store(&spinningrx, 0);
		pthread_mutex_unlock(&syncmutextx);

		if (ctr >= SOCK_RECONF_CTR)
			exit_with_error(ret);

		ksft_print_msg("Interface [%s] vector [Rx]\n",
			       ((struct ifobjectstruct *)arg)->opt_if);
		xsk_populate_fill_ring(((struct ifobjectstruct *)arg)->umem);

		struct pollfd fds[MAX_SOCKS] = {};
		int ret, i;

		TAILQ_INIT(&head);
		if (DEBUG_PKTDUMP) {
			pktbuf = malloc(sizeof(struct pktframe **) * NUM_FRAMES);
			if (!pktbuf)
				exit_with_error(errno);
		}

		for (i = 0; i < num_socks; i++) {
			fds[0].fd = xsk_socket__fd(((struct ifobjectstruct *)arg)->xsk->xsk);
			fds[0].events = POLLIN;
		}

		pthread_mutex_lock(&syncmutex);
		pthread_cond_signal(&signalrxcondition);
		pthread_mutex_unlock(&syncmutex);

		while (1) {
			if (opt_poll) {
				ret = poll(fds, num_socks, opt_timeout);
				if (ret <= 0)
					continue;
			}
			rx_pkt(((struct ifobjectstruct *)arg)->xsk, fds);

			if (pthread_create(&rxthread, NULL, worker_pkt_validate, NULL))
				exit_with_error(errno);
			pthread_join(rxthread, NULL);

			if (sigvar)
				break;
		}

		ksft_print_msg("Received %d packets on interface %s\n",
			       pktcounter, ((struct ifobjectstruct *)arg)->opt_if);

	}

	xsk_socket__delete(((struct ifobjectstruct *)arg)->xsk->xsk);
	(void)xsk_umem__delete(((struct ifobjectstruct *)arg)->umem->umem);
	pthread_exit(NULL);
}

static void testapp_validate(void)
{
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, THREAD_STACK);

	pthread_mutex_lock(&syncmutex);

	/*Spawn RX thread */
	if (pthread_create(&t0, &attr, worker_testapp_validate, (void *)ifdict[1]))
		exit_with_error(errno);

	struct timespec max_wait = {0, 0};

	if (clock_gettime(CLOCK_REALTIME, &max_wait))
		exit_with_error(errno);
	max_wait.tv_sec += TMOUT_SEC;

	if (pthread_cond_timedwait(&signalrxcondition, &syncmutex, &max_wait) == ETIMEDOUT)
		exit_with_error(errno);

	pthread_mutex_unlock(&syncmutex);

	/*Spawn TX thread */
	if (pthread_create(&t1, &attr, worker_testapp_validate, (void *)ifdict[0]))
		exit_with_error(errno);

	pthread_join(t1, NULL);
	pthread_join(t0, NULL);

	if (DEBUG_PKTDUMP) {
		worker_pkt_dump();
		for (int iter = 0; iter < NUM_FRAMES - 1; iter++) {
			free(pktbuf[iter]->payload);
			free(pktbuf[iter]);
		}
		free(pktbuf);
	}

	if (UUT == ORDER_CONTENT_VALIDATE_XDP_SKB) {
		if (opt_poll)
			ksft_test_result_pass("PASS: SKB POLL\n");
		else
			ksft_test_result_pass("PASS: SKB NOPOLL\n");
	} else if (UUT == ORDER_CONTENT_VALIDATE_XDP_DRV) {
		if (opt_poll)
			ksft_test_result_pass("PASS: DRV POLL\n");
		else
			ksft_test_result_pass("PASS: DRV NOPOLL\n");
	}
}

static void init_iface_config(void *ifaceconfig)
{
	/*Init interface0 */
	ifdict[0]->fv.vector = tx;
	memcpy(ifdict[0]->dst_mac, ((struct ifaceconfigobj *)ifaceconfig)->dst_mac, ETH_ALEN);
	memcpy(ifdict[0]->src_mac, ((struct ifaceconfigobj *)ifaceconfig)->src_mac, ETH_ALEN);
	ifdict[0]->dst_ip = ((struct ifaceconfigobj *)ifaceconfig)->dst_ip.s_addr;
	ifdict[0]->src_ip = ((struct ifaceconfigobj *)ifaceconfig)->src_ip.s_addr;
	ifdict[0]->dst_port = ((struct ifaceconfigobj *)ifaceconfig)->dst_port;
	ifdict[0]->src_port = ((struct ifaceconfigobj *)ifaceconfig)->src_port;

	/*Init interface1 */
	ifdict[1]->fv.vector = rx;
	memcpy(ifdict[1]->dst_mac, ((struct ifaceconfigobj *)ifaceconfig)->src_mac, ETH_ALEN);
	memcpy(ifdict[1]->src_mac, ((struct ifaceconfigobj *)ifaceconfig)->dst_mac, ETH_ALEN);
	ifdict[1]->dst_ip = ((struct ifaceconfigobj *)ifaceconfig)->src_ip.s_addr;
	ifdict[1]->src_ip = ((struct ifaceconfigobj *)ifaceconfig)->dst_ip.s_addr;
	ifdict[1]->dst_port = ((struct ifaceconfigobj *)ifaceconfig)->src_port;
	ifdict[1]->src_port = ((struct ifaceconfigobj *)ifaceconfig)->dst_port;
}

int main(int argc, char **argv)
{
	struct rlimit _rlim = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &_rlim))
		exit_with_error(errno);

	const char *MAC1 = "\x00\x0A\x56\x9E\xEE\x62";
	const char *MAC2 = "\x00\x0A\x56\x9E\xEE\x61";
	const char *IP1 = "192.168.100.162";
	const char *IP2 = "192.168.100.161";
	u16 UDP_DST_PORT = 2020;
	u16 UDP_SRC_PORT = 2121;

	ifaceconfig = (struct ifaceconfigobj *)malloc(sizeof(struct ifaceconfigobj));
	memcpy(ifaceconfig->dst_mac, MAC1, ETH_ALEN);
	memcpy(ifaceconfig->src_mac, MAC2, ETH_ALEN);
	inet_aton(IP1, &ifaceconfig->dst_ip);
	inet_aton(IP2, &ifaceconfig->src_ip);
	ifaceconfig->dst_port = UDP_DST_PORT;
	ifaceconfig->src_port = UDP_SRC_PORT;

	for (int i = 0; i < MAX_INTERFACES; i++) {
		ifdict[i] = (struct ifobjectstruct *)malloc(sizeof(struct ifobjectstruct));
		if (!ifdict[i])
			exit_with_error(errno);

		ifdict[i]->ifdict_index = i;
	}

	setlocale(LC_ALL, "");

	parse_command_line(argc, argv);

	NUM_FRAMES = ++opt_pkt_count;

	init_iface_config((void *)ifaceconfig);

	pthread_init_mutex();

	ksft_set_plan(1);
	testapp_validate();

	for (int i = 0; i < MAX_INTERFACES; i++)
		free(ifdict[i]);

	pthread_destroy_mutex();

	ksft_exit_pass();

	return 0;
}
