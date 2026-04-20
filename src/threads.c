#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include "lab.h"
#include "mac.h"

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
	int n, i;

	setaffinity(LAB_CPU_LOC);
	while (!ctx->stop) {
		lab_drain_cq_loc(&ctx->zc);
		lab_refill_fq_loc(&ctx->zc);

		while (lab_ring_try_pop(&ctx->w_to_loc, &j) == 0)
			(void)lab_tx_loc(&ctx->zc, j.umem_addr, j.len);

		n = lab_recv_loc(&ctx->zc, lens, addrs, LAB_BATCH);
		for (i = 0; i < n; i++) {
			j.umem_addr = addrs[i];
			j.len = lens[i];
			if (lab_ring_push_retry(&ctx->ing_to_mid, &j,
						&ctx->stop))
				break;
		}
		if (!n)
			sched_yield();
	}
	return NULL;
}

static void *wan_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	uint32_t lens[LAB_BATCH];
	uint64_t addrs[LAB_BATCH];
	struct lab_job j;
	int n, i;

	setaffinity(LAB_CPU_WAN);
	while (!ctx->stop) {
		lab_drain_cq_wan(&ctx->zc);
		lab_refill_fq_wan(&ctx->zc);

		while (lab_ring_try_pop(&ctx->w_to_wan, &j) == 0)
			(void)lab_tx_wan(&ctx->zc, j.umem_addr, j.len);

		n = lab_recv_wan(&ctx->zc, lens, addrs, LAB_BATCH);
		for (i = 0; i < n; i++) {
			j.umem_addr = addrs[i];
			j.len = lens[i];
			if (lab_ring_push_retry(&ctx->wan_to_mid, &j,
						&ctx->stop))
				break;
		}
		if (!n)
			sched_yield();
	}
	return NULL;
}

static void *mid_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	struct lab_job j;

	setaffinity(LAB_CPU_MID);
	while (!ctx->stop) {
		if (lab_ring_try_pop(&ctx->ing_to_mid, &j) == 0) {
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_WAN);
			ctx->stats.mid_to_wan++;
			lab_ring_push_retry(&ctx->w_to_wan, &j, &ctx->stop);
			continue;
		}
		if (lab_ring_try_pop(&ctx->wan_to_mid, &j) == 0) {
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_LOC);
			ctx->stats.mid_to_loc++;
			lab_ring_push_retry(&ctx->w_to_loc, &j, &ctx->stop);
			continue;
		}
		sched_yield();
	}
	return NULL;
}

static void *stats_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	struct lab_stats prev = { 0 };

	while (!ctx->stop) {
		sleep(1);
		struct lab_stats c = ctx->stats;

		fprintf(stderr,
			"[stats] rx_loc=%lu(+%lu) rx_wan=%lu(+%lu) "
			"mid2wan=%lu(+%lu) mid2loc=%lu(+%lu) "
			"tx_loc ok=%lu(+%lu) fail=%lu(+%lu) errno=%d(%s) "
			"tx_wan ok=%lu(+%lu) fail=%lu(+%lu) errno=%d(%s) "
			"cq_loc=%lu cq_wan=%lu fq_refill_loc=%lu fq_refill_wan=%lu pool=%u\n",
			c.rx_loc, c.rx_loc - prev.rx_loc,
			c.rx_wan, c.rx_wan - prev.rx_wan,
			c.mid_to_wan, c.mid_to_wan - prev.mid_to_wan,
			c.mid_to_loc, c.mid_to_loc - prev.mid_to_loc,
			c.tx_loc_ok, c.tx_loc_ok - prev.tx_loc_ok,
			c.tx_loc_fail, c.tx_loc_fail - prev.tx_loc_fail,
			c.last_tx_loc_errno,
			c.last_tx_loc_errno ? strerror(c.last_tx_loc_errno) :
					      "ok",
			c.tx_wan_ok, c.tx_wan_ok - prev.tx_wan_ok,
			c.tx_wan_fail, c.tx_wan_fail - prev.tx_wan_fail,
			c.last_tx_wan_errno,
			c.last_tx_wan_errno ? strerror(c.last_tx_wan_errno) :
					      "ok",
			c.cq_loc, c.cq_wan,
			c.fq_refill_loc, c.fq_refill_wan,
			ctx->zc.pool.n);
		fflush(stderr);
		prev = c;
	}
	return NULL;
}

int lab_run(struct lab_ctx *ctx, const char *loc_if, const char *wan_if,
	    const char *bpf_loc, const char *bpf_wan)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->zc.stats = &ctx->stats;
	if (lab_pair_open(&ctx->zc, loc_if, wan_if, bpf_loc, bpf_wan))
		return -1;
	ctx->zc.stats = &ctx->stats;
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
	if (pthread_create(&ctx->th_stats, NULL, stats_worker, ctx))
		goto err;
	return 0;

err:
	ctx->stop = 1;
	lab_ring_wake_all(&ctx->ing_to_mid);
	lab_ring_wake_all(&ctx->wan_to_mid);
	lab_ring_wake_all(&ctx->w_to_wan);
	lab_ring_wake_all(&ctx->w_to_loc);
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
	lab_ring_wake_all(&ctx->ing_to_mid);
	lab_ring_wake_all(&ctx->wan_to_mid);
	lab_ring_wake_all(&ctx->w_to_wan);
	lab_ring_wake_all(&ctx->w_to_loc);
}

void lab_ctx_join(struct lab_ctx *ctx)
{
	pthread_join(ctx->th_loc, NULL);
	pthread_join(ctx->th_mid, NULL);
	pthread_join(ctx->th_wan, NULL);
	pthread_join(ctx->th_stats, NULL);
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
}
