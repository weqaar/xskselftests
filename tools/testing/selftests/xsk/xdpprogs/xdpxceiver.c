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

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define MIN_PKT_SIZE 64

#define MAX_INTERFACES 2
#define MAX_INTERFACE_NAME_CHARS 7
#define MAX_INTERFACES_NAMESPACE_CHARS 10
#define MAX_MAC_STR 18
#define MAX_IP4_STR 16
#define MAX_IP6_STR 40

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

/*TESTS Specific*/
#define MAX_TEARDOWN_ITER 10
#define MAX_BIDI_ITER 2
enum TESTS {
	ORDER_CONTENT_VALIDATE_XDP_SKB = 1,
	ORDER_CONTENT_VALIDATE_XDP_DRV = 2,
};
u8 UUT;
u8 DEBUG_PKTDUMP;
u32 NUM_FRAMES;
u8 switchingNotify;

static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int opt_queue;
static u32 opt_batch_size = 64;
static int opt_pkt_count;
static u16 opt_pkt_size = MIN_PKT_SIZE;
static int opt_poll;
static int opt_teardown;
static int opt_bidi;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;
static int opt_mmap_flags;
static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static int opt_timeout = 1000;
static bool opt_need_wakeup = true;
static u32 opt_num_xsks;
static u32 prog_id;
static int num_socks = 1;
static u8 pkt_data[XSK_UMEM__DEFAULT_FRAME_SIZE];
static u32 pktCounter;
static int sigVar;
static u32 prevPkt = -1;

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_npkts;
	u32 outstanding_tx;
};

struct flow_vector {
	enum fvector {
		tx,
		rx,
		bidi,
		undef,
	} vector;
};
u8 bidi_pass;

struct generic_data {
	u32 seqnum;
};

struct ifObjectStruct {
	int opt_ifindex;
	int ifDict_index;
	char opt_if[MAX_INTERFACE_NAME_CHARS];
	char opt_ns[MAX_INTERFACES_NAMESPACE_CHARS];
	struct flow_vector fv;
	struct xsk_socket_info *xsk;
	struct xsk_umem_info *umem;
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	char dst_ip[MAX_IP4_STR];
	char src_ip[MAX_IP4_STR];
};
static struct ifObjectStruct *ifDict[MAX_INTERFACES];

/*packet*/
#define ETH_FCS_SIZE		4
#define PKT_HDR_SIZE		(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
				sizeof(struct udphdr))
#define PKT_SIZE		(opt_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE		(PKT_SIZE - sizeof(struct ethhdr))
#define UDP_PKT_SIZE		(IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE	(UDP_PKT_SIZE - sizeof(struct udphdr))

/*threads*/
#define TMOUT_SEC	(3)
#define EOT		(-1)
#define USLEEP_MAX	200000
#define THREAD_STACK	60000000
atomic_int spinningTx;
atomic_int spinningRx;
pthread_mutex_t syncMutex;
pthread_mutex_t syncMutexTx;
pthread_mutex_t syncMutexRx;
pthread_cond_t signalRxCondition;
pthread_cond_t signalTxCondition;
pthread_t t0, t1, rxthread, nsthread, rxDumpThread;
pthread_attr_t attr;

struct targs {
	bool retptr;
	int idx;
};

TAILQ_HEAD(head_s, pkt) head = TAILQ_HEAD_INITIALIZER(head);
struct head_s *headp;
struct pkt {
	char *pktFrame;

	TAILQ_ENTRY(pkt) pktNodes;
} *pktNodeRx, *pktNodeRxQ, *pktNodeRxDumpOut;

struct pktFrame {
	int pktID;
	char *payload;
} *pktObj;
struct pktFrame **pktBuf;

static void pthread_init_mutex(void)
{
	pthread_mutex_init(&syncMutex, NULL);
	pthread_mutex_init(&syncMutexTx, NULL);
	pthread_mutex_init(&syncMutexRx, NULL);
	pthread_cond_init(&signalRxCondition, NULL);
	pthread_cond_init(&signalTxCondition, NULL);
}

static void pthread_destroy_mutex(void)
{
	pthread_mutex_destroy(&syncMutex);
	pthread_mutex_destroy(&syncMutexTx);
	pthread_mutex_destroy(&syncMutexRx);
	pthread_cond_destroy(&signalRxCondition);
	pthread_cond_destroy(&signalTxCondition);
}

static void
__exit_with_error(int error, const char *file, const char *func, int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));
	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, \
						 __LINE__)

static void *memset32_htonl(void *dest, u32 val, u32 size)
{
	u32 *ptr = (u32 *) dest;
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
	u32 sum = (__force u32) csum;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__force __sum16) ~sum;
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
	return (u32) x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
		   __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (__force u32) sum;

	s += (__force u32) saddr;
	s += (__force u32) daddr;
#ifdef __BIG_ENDIAN__
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return (__force __wsum) from64to32(s);
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

static inline u16
udp_csum(u32 saddr, u32 daddr, u32 len, u8 proto, u16 *udp_pkt)
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
	/*
	 * unsigned char        h_dest [ETH_ALEN]
	 * unsigned char        h_source [ETH_ALEN]
	 */
	memcpy(eth_hdr->h_dest, ((struct ifObjectStruct *)data)->dst_mac,
	       ETH_ALEN);
	memcpy(eth_hdr->h_source, ((struct ifObjectStruct *)data)->src_mac,
	       ETH_ALEN);
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
	ip_hdr->saddr = htonl(0x0a0a0a10);
	ip_hdr->daddr = htonl(0x0a0a0a20);
	ip_hdr->check = 0;
}

static void gen_udp_hdr(void *data, struct udphdr *udp_hdr)
{
	udp_hdr->source = htons(0x1000);
	udp_hdr->dest = htons(0x1000);
	udp_hdr->len = htons(UDP_PKT_SIZE);
	memset32_htonl(pkt_data + PKT_HDR_SIZE,
		       htonl(((struct generic_data *)data)->seqnum),
		       UDP_PKT_DATA_SIZE);
}

static void gen_udp_csum(struct udphdr *udp_hdr, struct iphdr *ip_hdr)
{
	udp_hdr->check = 0;
	udp_hdr->check =
	    udp_csum(ip_hdr->saddr, ip_hdr->daddr, UDP_PKT_SIZE, IPPROTO_UDP,
		     (u16 *) udp_hdr);
}

static void gen_eth_frame(struct xsk_umem_info *umem, u64 addr)
{
	memcpy(xsk_umem__get_data(umem->buffer, addr), pkt_data, PKT_SIZE);
}

static void xsk_configure_umem(struct ifObjectStruct *data, void *buffer, u64 size)
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
	if (!data->umem) {
		fprintf(stderr, "ERROR: calloc \"%s\"\n", strerror(errno));
		ksft_test_result_fail("ERROR: calloc\n");
		ksft_exit_xfail();
	}

	ret = xsk_umem__create(&(data->umem)->umem, buffer, size,
			       &(data->umem)->fq, &(data->umem)->cq, &cfg);
	if (ret) {
		ksft_test_result_fail("ERROR: xsk_umem__create: %d\n", ret);
		ksft_exit_xfail();
	}

	(data->umem)->buffer = buffer;
}

static void xsk_populate_fill_ring(struct xsk_umem_info *umem)
{
	int ret, i;
	u32 idx;

	ret = xsk_ring_prod__reserve(&umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		exit_with_error(-ret);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
		    i * opt_xsk_frame_size;
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
}

static int xsk_configure_socket(struct ifObjectStruct *ifObject)
{
	struct xsk_socket_config cfg;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	ifObject->xsk = calloc(1, sizeof(struct xsk_socket_info));
	if (!ifObject->xsk) {
		fprintf(stderr, "ERROR: calloc \"%s\"\n", strerror(errno));
		ksft_test_result_fail("ERROR: calloc\n");
		ksft_exit_xfail();
	}

	(ifObject->xsk)->umem = ifObject->umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	if (opt_num_xsks > 1)
		cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	else
		cfg.libbpf_flags = 0;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;

	if (!opt_bidi) {
		rxr = (ifObject->fv.vector == rx) ? &(ifObject->xsk)->rx : NULL;
		txr = (ifObject->fv.vector == tx) ? &(ifObject->xsk)->tx : NULL;
	} else {
		rxr = &(ifObject->xsk)->rx;
		txr = &(ifObject->xsk)->tx;
	}

	ret = xsk_socket__create(&(ifObject->xsk)->xsk, ifObject->opt_if,
				 opt_queue, (ifObject->umem)->umem, rxr, txr,
				 &cfg);

	if (ret)
		return 1;

	ret =
	    bpf_get_link_xdp_id(ifObject->opt_ifindex, &prog_id, opt_xdp_flags);

	if (ret)
		return 2;

	return 0;
}

static struct option long_options[] = {
	{"interface", required_argument, 0, 'i'},
	{"queue", optional_argument, 0, 'q'},
	{"poll", no_argument, 0, 'p'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{"copy", no_argument, 0, 'c'},
	{"tear-down", no_argument, 0, 'T'},
	{"bidi", optional_argument, 0, 'B'},
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
	    "  -T, --tear-down      Tear down sockets by recreating them and running a test again for each of the 2 modes: SKB and DRV\n"
	    "  -B, --bidi           Bi-directional sockets test\n"
	    "  -D, --debug          Debug mode - dump packets L2 - L5\n"
	    "  -C, --tx-pkt-count=n Number of packets to send\n";
	fprintf(stderr, str, prog);
}

static bool switch_namespace(int idx)
{
	const char fqns[25] = "/var/run/netns/";

	strcat((char *)fqns, ifDict[idx]->opt_ns);

	int nsfd = open(fqns, O_RDONLY);

	if (nsfd == -1) {
		fprintf(stderr, "error: open %s\n", fqns);
		return false;
	}
	if (setns(nsfd, 0) == -1) {
		fprintf(stderr, "error: setns\n");
		return false;
	}

	return true;
};

static void *nsSwitchThread(void *args)
{

	if (switch_namespace(((struct targs *)args)->idx)) {

		ifDict[((struct targs *)args)->idx]->opt_ifindex =
		    if_nametoindex(ifDict[((struct targs *)args)->idx]->opt_if);
		if (!ifDict[((struct targs *)args)->idx]->opt_ifindex) {
			ksft_test_result_fail
			    ("KFAIL ERROR: interface \"%s\" does not exist\n",
			     ifDict[((struct targs *)args)->idx]->opt_if);
			((struct targs *)args)->retptr = false;
		} else {
			ksft_print_msg("Interface found: %s\n",
				ifDict[((struct targs *)args)->idx]->opt_if);
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
		if (!strcmp(ifDict[i]->opt_if, "")) {
			ret = false;
			ksft_test_result_fail
			    ("ERROR: Please provide at least two interfaces: -i <int>,<ns> -i <int>,<ns>. Namespace(ns) is OPTIONAL.");
		}
		if (strcmp(ifDict[i]->opt_ns, "")) {
			struct targs *Targs;

			Targs = (struct targs *)malloc(sizeof(struct targs));
			if (Targs == NULL) {
				fprintf(stderr, "ERROR: malloc \"%s\"\n",
					strerror(errno));
				ksft_test_result_fail("ERROR: malloc\n");
				ksft_exit_xfail();
			}

			Targs->idx = i;
			if (pthread_create
			    (&nsthread, NULL, nsSwitchThread, (void *)Targs)) {
				ksft_test_result_fail
				    ("ERROR: pthread_create\n");
				ksft_exit_xfail();
			}

			pthread_join(nsthread, NULL);

			if (Targs->retptr)
				printf("NS switched: %s\n", ifDict[i]->opt_ns);

			free(Targs);

		} else {
			ifDict[i]->opt_ifindex =
			    if_nametoindex(ifDict[i]->opt_if);
			if (!ifDict[i]->opt_ifindex) {
				ksft_test_result_fail
				    ("KFAIL ERROR: interface \"%s\" does not exist\n",
				     ifDict[i]->opt_if);
				ret = false;
			} else
				ksft_print_msg("Interface found: %s\n",
					       ifDict[i]->opt_if);
		}
	}
	return ret;
}

static void parse_command_line(int argc, char **argv)
{

	int option_index, interface_index = 0, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "i:q:pSNcTBDC:", long_options,
				&option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'i':
			if (interface_index == MAX_INTERFACES)
				break;
			char *sptr, *token;

			strcpy(ifDict[interface_index]->opt_if,
			       strtok_r(optarg, ",", &sptr));
			token = strtok_r(NULL, ",", &sptr);
			if (token)
				strcpy(ifDict[interface_index]->opt_ns, token);
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
		case 'T':
			opt_teardown = 1;
			break;
		case 'B':
			opt_bidi = 1;
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
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
	    errno == EBUSY || errno == ENETDOWN)
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

	pthread_mutex_lock(&syncMutexRx);
	for (i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		(void)xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		u64 orig = xsk_umem__extract_addr(addr);

		addr = xsk_umem__add_offset_to_addr(addr);
		pktNodeRx = malloc(sizeof(struct pkt) + PKT_SIZE);
		if (pktNodeRx == NULL) {
			fprintf(stderr, "ERROR: malloc \"%s\"\n",
				strerror(errno));
			ksft_test_result_fail("ERROR: malloc\n");
			ksft_exit_xfail();
		}

		pktNodeRx->pktFrame = (char *)malloc(PKT_SIZE);
		if (pktNodeRx->pktFrame  == NULL) {
			fprintf(stderr, "ERROR: malloc \"%s\"\n",
				strerror(errno));
			ksft_test_result_fail("ERROR: malloc\n");
			ksft_exit_xfail();
		}

		memcpy(pktNodeRx->pktFrame,
		       xsk_umem__get_data(xsk->umem->buffer, addr), PKT_SIZE);

		TAILQ_INSERT_HEAD(&head, pktNodeRx, pktNodes);

		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = orig;
	}
	pthread_mutex_unlock(&syncMutexRx);

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
		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx,
								  idx + i);
		tx_desc->addr =
		    (*frameptr + i) << XSK_UMEM__DEFAULT_FRAME_SHIFT;
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
			if ((((struct ifObjectStruct *)arg)->xsk)->
			    outstanding_tx) {
				complete_tx_only(((struct ifObjectStruct *)
						  arg)->xsk, opt_batch_size);
				pending =
				    !!(((struct ifObjectStruct *)arg)->xsk)->
				    outstanding_tx;
			}
		}
	} while (pending);
}

static void tx_only_all(void *arg)
{
	struct pollfd fds[MAX_SOCKS] = { };
	u32 frame_nb = 0;
	int pkt_cnt = 0;
	int i, ret;

	for (i = 0; i < num_socks; i++) {
		fds[i].fd =
		    xsk_socket__fd((((struct ifObjectStruct *)arg)->xsk)->xsk);
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

		tx_only(((struct ifObjectStruct *)arg)->xsk, &frame_nb,
			batch_size);

		pkt_cnt += batch_size;
	}

	if (opt_pkt_count)
		complete_tx_only_all(arg);
}

static void worker_pkt_dump(void)
{
	for (int iter = 0; iter < NUM_FRAMES - 1; iter++) {
		/*extract L2 frame */
		fprintf(stdout, "DEBUG>> L2: dst mac: ");
		for (int i = 0; i < ETH_ALEN; i++)
			printf("%02X",
			       ((struct ethhdr *)
					(pktBuf[iter]->payload))->h_dest[i]);

		fprintf(stdout, "\nDEBUG>> L2: src mac: ");
		for (int i = 0; i < ETH_ALEN; i++)
			printf("%02X",
			       ((struct ethhdr *)
					pktBuf[iter]->payload)->h_source[i]);

		/*extract L3 frame */
		fprintf(stdout, "\nDEBUG>> L3: ip_hdr->ihl: %02X\n",
			((struct iphdr *)(pktBuf[iter]->payload +
					  sizeof(struct ethhdr)))->ihl);

		/*extract L4 frame */
		fprintf(stdout, "DEBUG>> L4: udp_hdr->src: %04X\n",
			((struct udphdr *)(pktBuf[iter]->payload +
					   sizeof(struct ethhdr) +
					   sizeof(struct iphdr)))->source);

		/*extract L5 frame */
		int payload =
		    *((uint32_t *) (pktBuf[iter]->payload + PKT_HDR_SIZE));
		if (payload == EOT) {
			ksft_print_msg("End-of-tranmission frame received\n");
			break;
		}
		fprintf(stdout, "DEBUG>> L5: payload: %d\n", payload);
	}
}

static void *worker_pkt_validate(void *arg)
{
	u32 payloadSeqnum = -2;

	pthread_mutex_lock(&syncMutexRx);

	while (1) {
		pktNodeRxQ = malloc(sizeof(struct pkt));
		pktNodeRxQ = TAILQ_LAST(&head, head_s);
		if (pktNodeRxQ == NULL)
			break;

		payloadSeqnum =
		    *((uint32_t *) (pktNodeRxQ->pktFrame + PKT_HDR_SIZE));
		if ((DEBUG_PKTDUMP) && (payloadSeqnum != EOT)) {
			pktObj =
			    (struct pktFrame *)malloc(sizeof(struct pktFrame));
			pktObj->payload = (char *)malloc(PKT_SIZE);
			memcpy(pktObj->payload, pktNodeRxQ->pktFrame, PKT_SIZE);
			pktBuf[payloadSeqnum] = pktObj;
		}

		if (payloadSeqnum == EOT) {
			ksft_print_msg
			    ("End-of-tranmission frame received: PASS\n");
			sigVar = 1;
			break;
		}

		if (prevPkt + 1 != payloadSeqnum) {
			ksft_test_result_fail
			    ("ERROR: [%s] prevPkt [%d], payloadSeqnum [%d]\n",
			     __func__, prevPkt, payloadSeqnum);
			ksft_exit_xfail();
		}

		TAILQ_REMOVE(&head, pktNodeRxQ, pktNodes);
		free(pktNodeRxQ->pktFrame);
		free(pktNodeRxQ);
		pktNodeRxQ = NULL;
		prevPkt = payloadSeqnum;
		pktCounter++;
	}
	pthread_mutex_unlock(&syncMutexRx);
	pthread_exit(NULL);
}

static void *worker_testapp_validate(void *arg)
{
	void *bufs;
	int ret, ctr = 0;
	struct generic_data *data =
	    (struct generic_data *)malloc(sizeof(struct generic_data));
	struct ethhdr *eth_hdr = (struct ethhdr *)pkt_data;
	struct iphdr *ip_hdr =
	    (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	struct udphdr *udp_hdr =
	    (struct udphdr *)(pkt_data + sizeof(struct ethhdr) +
			      sizeof(struct iphdr));

	pthread_attr_setstacksize(&attr, THREAD_STACK);

	if (!bidi_pass) {
		bufs = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
			    PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1,
			    0);
		if (bufs == MAP_FAILED) {
			ksft_test_result_fail("ERROR: mmap failed\n");
			ksft_exit_xfail();
		}
		if (strcmp(((struct ifObjectStruct *)arg)->opt_ns, ""))
			switch_namespace(((struct ifObjectStruct *)
					  arg)->ifDict_index);

	}

	if (((struct ifObjectStruct *)arg)->fv.vector == tx) {
		if (!bidi_pass) {
			xsk_configure_umem((struct ifObjectStruct *)arg, bufs,
					   NUM_FRAMES * opt_xsk_frame_size);
			ret =
			    xsk_configure_socket((struct ifObjectStruct *)arg);

			/* Retry Create Socket if it fails as xsk_socket__create()
			 * is asynchronous
			 *
			 * Essential to lock Mutex here to prevent Tx thread from
			 * entering before Rx and causing a deadlock
			 */
			pthread_mutex_lock(&syncMutexTx);
			while ((ret != 0) && (ctr < 10)) {
				atomic_store(&spinningTx, 1);
				xsk_configure_umem((struct ifObjectStruct *)arg,
						   bufs,
						   NUM_FRAMES *
						   opt_xsk_frame_size);
				ret =
				    xsk_configure_socket((struct ifObjectStruct
							  *)arg);
				usleep(USLEEP_MAX);
				ctr++;
			}
			atomic_store(&spinningTx, 0);
			pthread_mutex_unlock(&syncMutexTx);

			if (ctr >= 10) {
				ksft_test_result_fail
				    ("ERROR: xsk_configure_socket [xsk_socket__create]: %d\n",
				     ret);
			}
		}
		int spinningRxCtr = 0;

		while ((atomic_load(&spinningRx)) && (spinningRxCtr < 10)) {
			spinningRxCtr++;
			usleep(USLEEP_MAX);
		}

		ksft_print_msg("Interface [%s] vector [Tx]\n",
			       ((struct ifObjectStruct *)arg)->opt_if);
		for (int i = 0; i < NUM_FRAMES; i++) {
			/*send EOT frame */
			if (i == (NUM_FRAMES - 1))
				data->seqnum = -1;
			else
				data->seqnum = i;
			gen_udp_hdr((void *)data, udp_hdr);
			gen_ip_hdr((void *)arg, ip_hdr);
			gen_udp_csum(udp_hdr, ip_hdr);
			gen_eth_hdr((void *)arg, eth_hdr);
			gen_eth_frame(((struct ifObjectStruct *)arg)->umem,
				      i * opt_xsk_frame_size);
		}

		free(data);

		ksft_print_msg("Sending %d packets on interface %s\n",
			       (opt_pkt_count - 1),
			       ((struct ifObjectStruct *)arg)->opt_if);
		tx_only_all(arg);
	}

	else if (((struct ifObjectStruct *)arg)->fv.vector == rx) {
		if (!bidi_pass) {
			xsk_configure_umem((struct ifObjectStruct *)arg, bufs,
					   NUM_FRAMES * opt_xsk_frame_size);

			ret =
			    xsk_configure_socket((struct ifObjectStruct *)arg);

			/* Retry Create Socket if it fails as xsk_socket__create() is
			 * asynchronous
			 *
			 * Essential to lock Mutex here to prevent Tx thread from entering
			 * before Rx and causing a deadlock
			 */
			pthread_mutex_lock(&syncMutexTx);
			while ((ret != 0) && (ctr < 10)) {
				atomic_store(&spinningRx, 1);
				xsk_configure_umem((struct ifObjectStruct *)arg,
						   bufs,
						   NUM_FRAMES *
						   opt_xsk_frame_size);
				ret =
				    xsk_configure_socket((struct ifObjectStruct
							  *)arg);
				usleep(USLEEP_MAX);
				ctr++;
			}
			atomic_store(&spinningRx, 0);
			pthread_mutex_unlock(&syncMutexTx);

			if (ctr >= 10) {
				ksft_test_result_fail
				    ("ERROR: xsk_configure_socket [xsk_socket__create]: %d\n",
				     ret);
			}
		}

		ksft_print_msg("Interface [%s] vector [Rx]\n",
			       ((struct ifObjectStruct *)arg)->opt_if);
		xsk_populate_fill_ring(((struct ifObjectStruct *)arg)->umem);

		struct pollfd fds[MAX_SOCKS] = { };
		int ret, i;

		TAILQ_INIT(&head);
		if (DEBUG_PKTDUMP) {
			pktBuf = malloc(sizeof(struct pktFrame **) * NUM_FRAMES);
			if (pktBuf == NULL) {
				fprintf(stderr, "ERROR: malloc \"%s\"\n",
					strerror(errno));
				ksft_test_result_fail("ERROR: malloc\n");
				ksft_exit_xfail();
			}
		}

		for (i = 0; i < num_socks; i++) {
			fds[0].fd = xsk_socket__fd((((struct ifObjectStruct *)
						     arg)->xsk)->xsk);
			fds[0].events = POLLIN;
		}

		pthread_mutex_lock(&syncMutex);
		pthread_cond_signal(&signalRxCondition);
		pthread_mutex_unlock(&syncMutex);

		while (1) {

			if (opt_poll) {
				ret = poll(fds, num_socks, opt_timeout);
				if (ret <= 0)
					continue;
			}
			rx_pkt(((struct ifObjectStruct *)arg)->xsk, fds);

			if (pthread_create
			    (&rxthread, NULL, worker_pkt_validate, NULL)) {
				fprintf(stderr, "Thread create error: %s\n",
					strerror(errno));
				ksft_test_result_fail
				    ("ERROR: pthread_create\n");
				ksft_exit_xfail();
			}
			pthread_join(rxthread, NULL);

			if (sigVar)
				break;
		}

		ksft_print_msg("Received %d packets on interface %s\n",
			       pktCounter,
			       ((struct ifObjectStruct *)arg)->opt_if);

		if (opt_teardown)
			ksft_print_msg("Destroying socket\n");
	}

	if (!(opt_bidi) || ((opt_bidi) && (bidi_pass > 0))) {
		xsk_socket__delete((((struct ifObjectStruct *)arg)->xsk)->xsk);
		(void)
		    xsk_umem__delete((((struct ifObjectStruct *)arg)->
				      umem)->umem);
	}
	pthread_exit(NULL);
}

static void testapp_validate(void)
{
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, THREAD_STACK);

	if ((opt_bidi) && (bidi_pass > 0)) {
		pthread_init_mutex();
		if (switchingNotify == 0) {
			ksft_print_msg("Switching Tx/Rx vectors\n");
			switchingNotify++;
		}
	}

	pthread_mutex_lock(&syncMutex);

	/*Spawn RX thread */
	if (!(opt_bidi) || ((opt_bidi) && (bidi_pass == 0))) {
		if (pthread_create
		    (&t0, &attr, worker_testapp_validate,
		     (void *)ifDict[1])) {
			fprintf(stderr, "Thread create error: %s\n",
				strerror(errno));
			ksft_test_result_fail
			    ("ERROR: pthread_create\n");
			ksft_exit_xfail();
		}
	} else if ((opt_bidi) && (bidi_pass > 0)) {
		/*switch Tx/Rx vectors */
		ifDict[0]->fv.vector = rx;
		if (pthread_create
		    (&t0, &attr, worker_testapp_validate,
		     (void *)ifDict[0])) {
			fprintf(stderr, "Thread create error: %s\n",
				strerror(errno));
			ksft_test_result_fail
			    ("ERROR: pthread_create\n");
			ksft_exit_xfail();
		}
	}
	struct timespec max_wait = { 0, 0 };

	if (clock_gettime(CLOCK_REALTIME, &max_wait))
		perror("Error clock_gettime: ");
	max_wait.tv_sec += TMOUT_SEC;

	if (pthread_cond_timedwait
	    (&signalRxCondition, &syncMutex, &max_wait) == ETIMEDOUT) {
		ksft_test_result_fail("ERROR: RX timeout\n");
		ksft_exit_xfail();
	}
	pthread_mutex_unlock(&syncMutex);

	/*Spawn TX thread */
	if (!(opt_bidi) || ((opt_bidi) && (bidi_pass == 0))) {
		if (pthread_create
		    (&t1, &attr, worker_testapp_validate,
		     (void *)ifDict[0])) {
			fprintf(stderr, "Thread create error: %s\n",
				strerror(errno));
			ksft_test_result_fail
			    ("ERROR: pthread_create\n");
			ksft_exit_xfail();
		}
	} else if ((opt_bidi) && (bidi_pass > 0)) {
		/*switch Tx/Rx vectors */
		ifDict[1]->fv.vector = tx;
		if (pthread_create
		    (&t1, &attr, worker_testapp_validate,
		     (void *)ifDict[1])) {
			fprintf(stderr, "Thread create error: %s\n",
				strerror(errno));
			ksft_test_result_fail
			    ("ERROR: pthread_create\n");
			ksft_exit_xfail();
		}
	}

	pthread_join(t1, NULL);
	pthread_join(t0, NULL);

	if (DEBUG_PKTDUMP) {
		worker_pkt_dump();
		for (int iter = 0; iter < NUM_FRAMES - 1; iter++) {
			free(pktBuf[iter]->payload);
			free(pktBuf[iter]);
		}
		free(pktBuf);
	}

	if ((!opt_teardown) && (!opt_bidi)) {
		if (UUT == ORDER_CONTENT_VALIDATE_XDP_SKB) {
			ksft_test_result_pass
			    ("PASS: ORDER_CONTENT_VALIDATE_XDP_SKB\n");
		} else if (UUT == ORDER_CONTENT_VALIDATE_XDP_DRV) {
			ksft_test_result_pass
			    ("PASS: ORDER_CONTENT_VALIDATE_XDP_DRV\n");
		}
	}
}

static void testapp_socket_teardown(void)
{
	ksft_print_msg("Testing Socket Teardown\n");
	for (int i = 0; i < MAX_TEARDOWN_ITER; i++) {
		pktCounter = 0;
		prevPkt = -1;
		sigVar = 0;
		ksft_print_msg("Creating socket\n");
		testapp_validate();
	}
	if (UUT == ORDER_CONTENT_VALIDATE_XDP_SKB) {
		ksft_test_result_pass
		    ("PASS: ORDER_CONTENT_VALIDATE_XDP_SKB Socket Teardown\n");
	} else if (UUT == ORDER_CONTENT_VALIDATE_XDP_DRV) {
		ksft_test_result_pass
		    ("PASS: ORDER_CONTENT_VALIDATE_XDP_DRV Socket Teardown\n");
	}
}

static void testapp_socket_bidi(void)
{
	ksft_print_msg("Testing Bi-directional Sockets\n");
	for (int i = 0; i < MAX_BIDI_ITER; i++) {
		pktCounter = 0;
		prevPkt = -1;
		sigVar = 0;
		ksft_print_msg("Creating socket\n");
		testapp_validate();
		bidi_pass++;
	}
	if (UUT == ORDER_CONTENT_VALIDATE_XDP_SKB) {
		ksft_test_result_pass
		    ("PASS: ORDER_CONTENT_VALIDATE_XDP_SKB BiDi Test\n");
	} else if (UUT == ORDER_CONTENT_VALIDATE_XDP_DRV) {
		ksft_test_result_pass
		    ("PASS: ORDER_CONTENT_VALIDATE_XDP_DRV BiDi Test\n");
	}
}

static void init_iface_config(void)
{
	/*Init interface0 */
	ifDict[0]->fv.vector = tx;

	memcpy(ifDict[0]->dst_mac, "\x00\x0A\x56\x9E\xEE\x62", ETH_ALEN);
	memcpy(ifDict[0]->src_mac, "\x00\x0A\x56\x9E\xEE\x61", ETH_ALEN);

	strcpy(ifDict[0]->dst_ip, "192.168.100.62");
	strcpy(ifDict[0]->src_ip, "192.168.100.61");

	/*Init interface1 */
	ifDict[1]->fv.vector = rx;

	memcpy(ifDict[1]->src_mac, "\x00\x0A\x56\x9E\xEE\x62", ETH_ALEN);
	memcpy(ifDict[1]->dst_mac, "\x00\x0A\x56\x9E\xEE\x61", ETH_ALEN);

	strcpy(ifDict[1]->dst_ip, "192.168.100.61");
	strcpy(ifDict[1]->src_ip, "192.168.100.62");
}

int main(int argc, char **argv)
{
	struct rlimit _rlim = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &_rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < MAX_INTERFACES; i++) {
		ifDict[i] = (struct ifObjectStruct *)
				malloc(sizeof(struct ifObjectStruct));
		if (ifDict[i] == NULL) {
			fprintf(stderr, "ERROR: malloc \"%s\"\n",
				strerror(errno));
			ksft_test_result_fail("ERROR: malloc\n");
			ksft_exit_xfail();
		}

		ifDict[i]->ifDict_index = i;
	}

	setlocale(LC_ALL, "");

	parse_command_line(argc, argv);

	NUM_FRAMES = ++opt_pkt_count;

	init_iface_config();

	pthread_init_mutex();

	if ((UUT == ORDER_CONTENT_VALIDATE_XDP_SKB) && (!opt_teardown)
	    && (!opt_bidi)) {
		ksft_set_plan(1);
		testapp_validate();
	} else if ((UUT == ORDER_CONTENT_VALIDATE_XDP_DRV) && (!opt_teardown)
		   && (!opt_bidi)) {
		ksft_set_plan(1);
		testapp_validate();
	} else if (opt_teardown) {
		ksft_set_plan(1);
		testapp_socket_teardown();
	} else if (opt_bidi) {
		ksft_set_plan(1);
		testapp_socket_bidi();
	}

	for (int i = 0; i < MAX_INTERFACES; i++)
		free(ifDict[i]);

	pthread_destroy_mutex();

	ksft_exit_pass();

	return 0;
}
