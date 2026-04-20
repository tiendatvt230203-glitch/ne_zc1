#ifndef LAB_H
#define LAB_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <xdp/xsk.h>

struct bpf_object;

#define LAB_RING       4096u
#define LAB_FRAME      4096u
#define LAB_N_FRAMES   8192u
#define LAB_BATCH      64u
#define LAB_FQ_INIT    2048u
#define LAB_CPU_LOC    0u
#define LAB_CPU_MID    3u
#define LAB_CPU_WAN    11u

enum lab_dir {
	LAB_DIR_TO_WAN = 0,
	LAB_DIR_TO_LOC = 1,
};

struct lab_job {
	uint64_t umem_addr;
	uint32_t len;
};

struct lab_ring {
	struct lab_job *buf;
	uint32_t cap;
	uint32_t mask;
	__attribute__((aligned(64))) volatile uint32_t head;
	__attribute__((aligned(64))) volatile uint32_t tail;
};

struct lab_pool {
	pthread_mutex_t mu;
	uint64_t *stack;
	uint32_t cap;
	uint32_t n;
};

struct lab_zc_port {
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	int ifindex;
};

struct lab_pair {
	void *bufs;
	size_t bufsize;
	uint32_t frame_size;
	uint32_t n_frames;
	struct xsk_umem *umem;
	struct lab_zc_port loc;
	struct lab_zc_port wan;
	struct lab_pool pool;
	struct bpf_object *bpf_loc;
	struct bpf_object *bpf_wan;
	uint8_t xdp_loc_on;
	uint8_t xdp_wan_on;
};

int lab_ring_init(struct lab_ring *r, uint32_t cap);
void lab_ring_destroy(struct lab_ring *r);
int lab_ring_try_pop(struct lab_ring *r, struct lab_job *j);
int lab_ring_try_push(struct lab_ring *r, const struct lab_job *j);
int lab_ring_push_retry(struct lab_ring *r, const struct lab_job *j,
			volatile sig_atomic_t *stop);
uint32_t lab_ring_count(const struct lab_ring *r);
void lab_ring_wake_all(struct lab_ring *r);

int lab_pool_init(struct lab_pool *p, uint32_t cap);
void lab_pool_destroy(struct lab_pool *p);
uint32_t lab_pool_push(struct lab_pool *p, const uint64_t *addrs, uint32_t n);
uint32_t lab_pool_pop(struct lab_pool *p, uint64_t *addrs, uint32_t n);

int lab_pair_open(struct lab_pair *p, const char *loc_if, const char *wan_if,
		  const char *bpf_loc_o, const char *bpf_wan_o);
void lab_pair_close(struct lab_pair *p);

int lab_recv_loc(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max);
int lab_recv_wan(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max);
int lab_tx_drain_loc(struct lab_pair *p, struct lab_ring *src);
int lab_tx_drain_wan(struct lab_pair *p, struct lab_ring *src);
void lab_drain_cq_loc(struct lab_pair *p);
void lab_drain_cq_wan(struct lab_pair *p);
void lab_refill_fq_loc(struct lab_pair *p);
void lab_refill_fq_wan(struct lab_pair *p);

void *lab_ptr(struct lab_pair *p, uint64_t addr);

struct lab_ctx {
	volatile sig_atomic_t stop;
	struct lab_pair zc;
	struct lab_ring ing_to_mid;
	struct lab_ring wan_to_mid;
	struct lab_ring w_to_wan;
	struct lab_ring w_to_loc;
	pthread_t th_loc;
	pthread_t th_mid;
	pthread_t th_wan;
};

int lab_run(struct lab_ctx *ctx, const char *loc_if, const char *wan_if,
	    const char *bpf_loc, const char *bpf_wan);
void lab_ctx_stop(struct lab_ctx *ctx);
void lab_ctx_join(struct lab_ctx *ctx);

#endif
