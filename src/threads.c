#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include "lab.h"
#include "mac.h"

static inline void cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#else
	__asm__ volatile("" ::: "memory");
#endif
}

static void setaffinity(unsigned int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static void rewrite_eth(struct lab_pair *zc, uint64_t addr, enum lab_dir d)
{
	uint8_t *pkt = lab_ptr(zc, addr);
	static const uint8_t wan_dst[] = { MAC_WAN_DST };
	static const uint8_t wan_src[] = { MAC_WAN_SRC };
	static const uint8_t loc_dst[] = { MAC_LOC_DST };
	static const uint8_t loc_src[] = { MAC_LOC_SRC };

	if (d == LAB_DIR_TO_WAN) {
		memcpy(pkt, wan_dst, ETH_ALEN);
		memcpy(pkt + ETH_ALEN, wan_src, ETH_ALEN);
	} else {
		memcpy(pkt, loc_dst, ETH_ALEN);
		memcpy(pkt + ETH_ALEN, loc_src, ETH_ALEN);
	}
}

static void *loc_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	uint32_t lens[LAB_BATCH];
	uint64_t addrs[LAB_BATCH];
	struct lab_job j;
	int n, i, tx_sent;

	setaffinity(LAB_CPU_LOC);
	while (!ctx->stop) {
		lab_drain_cq_loc(&ctx->zc);
		lab_refill_fq_loc(&ctx->zc);

		tx_sent = lab_tx_drain_loc(&ctx->zc, &ctx->w_to_loc);

		n = lab_recv_loc(&ctx->zc, lens, addrs, LAB_BATCH);
		for (i = 0; i < n; i++) {
			j.umem_addr = addrs[i];
			j.len = lens[i];
			if (lab_ring_push_retry(&ctx->ing_to_mid, &j,
						&ctx->stop))
				break;
		}
		if (!n && !tx_sent)
			cpu_relax();
	}
	return NULL;
}

static void *wan_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	uint32_t lens[LAB_BATCH];
	uint64_t addrs[LAB_BATCH];
	struct lab_job j;
	int n, i, tx_sent;

	setaffinity(LAB_CPU_WAN);
	while (!ctx->stop) {
		lab_drain_cq_wan(&ctx->zc);
		lab_refill_fq_wan(&ctx->zc);

		tx_sent = lab_tx_drain_wan(&ctx->zc, &ctx->w_to_wan);

		n = lab_recv_wan(&ctx->zc, lens, addrs, LAB_BATCH);
		for (i = 0; i < n; i++) {
			j.umem_addr = addrs[i];
			j.len = lens[i];
			if (lab_ring_push_retry(&ctx->wan_to_mid, &j,
						&ctx->stop))
				break;
		}
		if (!n && !tx_sent)
			cpu_relax();
	}
	return NULL;
}

static void *mid_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	struct lab_job j;
	int did;

	setaffinity(LAB_CPU_MID);
	while (!ctx->stop) {
		did = 0;
		if (lab_ring_try_pop(&ctx->ing_to_mid, &j) == 0) {
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_WAN);
			lab_ring_push_retry(&ctx->w_to_wan, &j, &ctx->stop);
			did = 1;
		}
		if (lab_ring_try_pop(&ctx->wan_to_mid, &j) == 0) {
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_LOC);
			lab_ring_push_retry(&ctx->w_to_loc, &j, &ctx->stop);
			did = 1;
		}
		if (!did)
			cpu_relax();
	}
	return NULL;
}

int lab_run(struct lab_ctx *ctx, const char *loc_if, const char *wan_if,
	    const char *bpf_loc, const char *bpf_wan)
{
	memset(ctx, 0, sizeof(*ctx));
	if (lab_pair_open(&ctx->zc, loc_if, wan_if, bpf_loc, bpf_wan))
		return -1;
	if (lab_ring_init(&ctx->ing_to_mid, LAB_RING) ||
	    lab_ring_init(&ctx->wan_to_mid, LAB_RING) ||
	    lab_ring_init(&ctx->w_to_wan, LAB_RING) ||
	    lab_ring_init(&ctx->w_to_loc, LAB_RING)) {
		lab_pair_close(&ctx->zc);
		return -1;
	}
	ctx->stop = 0;

	if (pthread_create(&ctx->th_loc, NULL, loc_worker, ctx))
		goto err;
	if (pthread_create(&ctx->th_mid, NULL, mid_worker, ctx))
		goto err;
	if (pthread_create(&ctx->th_wan, NULL, wan_worker, ctx))
		goto err;
	return 0;

err:
	ctx->stop = 1;
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
	return -1;
}

void lab_ctx_stop(struct lab_ctx *ctx)
{
	ctx->stop = 1;
}

void lab_ctx_join(struct lab_ctx *ctx)
{
	pthread_join(ctx->th_loc, NULL);
	pthread_join(ctx->th_mid, NULL);
	pthread_join(ctx->th_wan, NULL);
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
}
