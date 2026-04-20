#include <errno.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#include "lab.h"

static inline void cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#else
	__asm__ volatile("" ::: "memory");
#endif
}

static int lab_xskmap_bind(struct xsk_socket *xsk, int map_fd)
{
	int key = 0;
	int xfd;

	if (!xsk || map_fd < 0)
		return -1;
	xfd = xsk_socket__fd(xsk);
	if (xfd < 0)
		return -1;
	if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
		return 0;
	return bpf_map_update_elem(map_fd, &key, &xfd, BPF_ANY);
}

int lab_ring_init(struct lab_ring *r, uint32_t cap)
{
	memset(r, 0, sizeof(*r));
	if (cap == 0 || (cap & (cap - 1)))
		return -1;
	r->buf = calloc(cap, sizeof(struct lab_job));
	if (!r->buf)
		return -1;
	r->cap = cap;
	r->mask = cap - 1;
	r->head = 0;
	r->tail = 0;
	return 0;
}

void lab_ring_destroy(struct lab_ring *r)
{
	if (!r->buf)
		return;
	free(r->buf);
	r->buf = NULL;
}

void lab_ring_wake_all(struct lab_ring *r)
{
	(void)r;
}

int lab_ring_try_push(struct lab_ring *r, const struct lab_job *j)
{
	uint32_t head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
	uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);

	if ((uint32_t)(head - tail) >= r->cap)
		return -1;
	r->buf[head & r->mask] = *j;
	__atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
	return 0;
}

int lab_ring_try_pop(struct lab_ring *r, struct lab_job *j)
{
	uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
	uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);

	if (tail == head)
		return -1;
	*j = r->buf[tail & r->mask];
	__atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);
	return 0;
}

int lab_ring_push_retry(struct lab_ring *r, const struct lab_job *j,
			volatile sig_atomic_t *stop)
{
	while (!*stop) {
		if (lab_ring_try_push(r, j) == 0)
			return 0;
		cpu_relax();
	}
	return -1;
}

int lab_pool_init(struct lab_pool *p, uint32_t cap)
{
	memset(p, 0, sizeof(*p));
	p->stack = calloc(cap, sizeof(uint64_t));
	if (!p->stack)
		return -1;
	if (pthread_mutex_init(&p->mu, NULL)) {
		free(p->stack);
		p->stack = NULL;
		return -1;
	}
	p->cap = cap;
	p->n = 0;
	return 0;
}

void lab_pool_destroy(struct lab_pool *p)
{
	if (!p->stack)
		return;
	pthread_mutex_destroy(&p->mu);
	free(p->stack);
	p->stack = NULL;
}

uint32_t lab_pool_push(struct lab_pool *p, const uint64_t *addrs, uint32_t n)
{
	uint32_t pushed = 0;

	pthread_mutex_lock(&p->mu);
	while (pushed < n && p->n < p->cap)
		p->stack[p->n++] = addrs[pushed++];
	pthread_mutex_unlock(&p->mu);
	return pushed;
}

uint32_t lab_pool_pop(struct lab_pool *p, uint64_t *addrs, uint32_t n)
{
	uint32_t popped = 0;

	pthread_mutex_lock(&p->mu);
	while (popped < n && p->n > 0)
		addrs[popped++] = p->stack[--p->n];
	pthread_mutex_unlock(&p->mu);
	return popped;
}

void *lab_ptr(struct lab_pair *p, uint64_t addr)
{
	return xsk_umem__get_data(p->bufs, addr);
}

static int lab_sock_open(struct lab_pair *p, struct lab_zc_port *port,
			 const char *ifn)
{
	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
	};

	return xsk_socket__create_shared(&port->xsk, ifn, 0, p->umem,
					 &port->rx, &port->tx,
					 &port->fq, &port->cq, &cfg);
}

int lab_pair_open(struct lab_pair *p, const char *loc_if, const char *wan_if,
		  const char *bpf_loc_o, const char *bpf_wan_o)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	struct xsk_umem_config ucfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = LAB_FRAME,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct bpf_program *pl = NULL, *pw = NULL;
	struct bpf_map *ml, *mw;
	uint64_t addrs[LAB_BATCH];
	uint32_t i;
	int err;

	memset(p, 0, sizeof(*p));
	p->frame_size = LAB_FRAME;
	p->n_frames = LAB_N_FRAMES;
	p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;

	(void)setrlimit(RLIMIT_MEMLOCK, &rl);

	p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p->bufs == MAP_FAILED) {
		p->bufs = NULL;
		return -1;
	}

	if (lab_pool_init(&p->pool, p->n_frames))
		goto err_mmap;

	for (i = 0; i < p->n_frames; i++) {
		uint64_t a = (uint64_t)i * p->frame_size;

		(void)lab_pool_push(&p->pool, &a, 1);
	}

	err = xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->loc.fq,
			       &p->loc.cq, &ucfg);
	if (err)
		goto err_pool;

	if (lab_sock_open(p, &p->loc, loc_if))
		goto err_umem;
	p->loc.ifindex = if_nametoindex(loc_if);
	if (!p->loc.ifindex)
		goto err_loc_xsk;

	if (lab_sock_open(p, &p->wan, wan_if))
		goto err_loc_xsk;
	p->wan.ifindex = if_nametoindex(wan_if);
	if (!p->wan.ifindex)
		goto err_wan_xsk;

	{
		uint32_t want = ucfg.fill_size;
		uint32_t got;
		uint32_t idx;
		uint32_t k;

		got = lab_pool_pop(&p->pool, addrs,
				   want > LAB_BATCH ? LAB_BATCH : want);
		while (got > 0) {
			if (xsk_ring_prod__reserve(&p->loc.fq, got, &idx) !=
			    got)
				goto err_wan_xsk;
			for (k = 0; k < got; k++)
				*xsk_ring_prod__fill_addr(&p->loc.fq,
							  idx + k) = addrs[k];
			xsk_ring_prod__submit(&p->loc.fq, got);
			want -= got;
			if (!want)
				break;
			got = lab_pool_pop(&p->pool, addrs,
					   want > LAB_BATCH ? LAB_BATCH :
							      want);
		}
	}

	{
		uint32_t want = ucfg.fill_size;
		uint32_t got;
		uint32_t idx;
		uint32_t k;

		got = lab_pool_pop(&p->pool, addrs,
				   want > LAB_BATCH ? LAB_BATCH : want);
		while (got > 0) {
			if (xsk_ring_prod__reserve(&p->wan.fq, got, &idx) !=
			    got)
				goto err_wan_xsk;
			for (k = 0; k < got; k++)
				*xsk_ring_prod__fill_addr(&p->wan.fq,
							  idx + k) = addrs[k];
			xsk_ring_prod__submit(&p->wan.fq, got);
			want -= got;
			if (!want)
				break;
			got = lab_pool_pop(&p->pool, addrs,
					   want > LAB_BATCH ? LAB_BATCH :
							      want);
		}
	}

	p->bpf_loc = bpf_object__open_file(bpf_loc_o, NULL);
	p->bpf_wan = bpf_object__open_file(bpf_wan_o, NULL);
	if (!p->bpf_loc || !p->bpf_wan)
		goto err_wan_xsk;

	if (bpf_object__load(p->bpf_loc) || bpf_object__load(p->bpf_wan))
		goto err_bpf;

	pl = bpf_object__find_program_by_name(p->bpf_loc, "xdp_redirect_prog");
	pw = bpf_object__find_program_by_name(p->bpf_wan,
					      "xdp_wan_redirect_prog");
	if (!pl || !pw)
		goto err_bpf;

	if (bpf_xdp_attach(p->loc.ifindex, bpf_program__fd(pl),
			   XDP_FLAGS_DRV_MODE, NULL))
		goto err_bpf;
	p->xdp_loc_on = 1;

	if (bpf_xdp_attach(p->wan.ifindex, bpf_program__fd(pw),
			   XDP_FLAGS_DRV_MODE, NULL))
		goto err_bpf;
	p->xdp_wan_on = 1;

	ml = bpf_object__find_map_by_name(p->bpf_loc, "xsks_map");
	mw = bpf_object__find_map_by_name(p->bpf_wan, "wan_xsks_map");
	if (!ml || !mw)
		goto err_xdp;
	if (lab_xskmap_bind(p->loc.xsk, bpf_map__fd(ml)) ||
	    lab_xskmap_bind(p->wan.xsk, bpf_map__fd(mw)))
		goto err_xdp;

	return 0;

err_xdp:
	if (p->xdp_wan_on) {
		bpf_xdp_detach(p->wan.ifindex, XDP_FLAGS_DRV_MODE, NULL);
		p->xdp_wan_on = 0;
	}
	if (p->xdp_loc_on) {
		bpf_xdp_detach(p->loc.ifindex, XDP_FLAGS_DRV_MODE, NULL);
		p->xdp_loc_on = 0;
	}
err_bpf:
	if (p->bpf_wan)
		bpf_object__close(p->bpf_wan);
	p->bpf_wan = NULL;
	if (p->bpf_loc)
		bpf_object__close(p->bpf_loc);
	p->bpf_loc = NULL;
err_wan_xsk:
	xsk_socket__delete(p->wan.xsk);
	p->wan.xsk = NULL;
err_loc_xsk:
	xsk_socket__delete(p->loc.xsk);
	p->loc.xsk = NULL;
err_umem:
	xsk_umem__delete(p->umem);
	p->umem = NULL;
err_pool:
	lab_pool_destroy(&p->pool);
err_mmap:
	munmap(p->bufs, p->bufsize);
	p->bufs = NULL;
	return -1;
}

void lab_pair_close(struct lab_pair *p)
{
	if (p->xdp_wan_on) {
		bpf_xdp_detach(p->wan.ifindex, XDP_FLAGS_DRV_MODE, NULL);
		p->xdp_wan_on = 0;
	}
	if (p->xdp_loc_on) {
		bpf_xdp_detach(p->loc.ifindex, XDP_FLAGS_DRV_MODE, NULL);
		p->xdp_loc_on = 0;
	}
	if (p->bpf_wan) {
		bpf_object__close(p->bpf_wan);
		p->bpf_wan = NULL;
	}
	if (p->bpf_loc) {
		bpf_object__close(p->bpf_loc);
		p->bpf_loc = NULL;
	}
	if (p->wan.xsk) {
		xsk_socket__delete(p->wan.xsk);
		p->wan.xsk = NULL;
	}
	if (p->loc.xsk) {
		xsk_socket__delete(p->loc.xsk);
		p->loc.xsk = NULL;
	}
	if (p->umem) {
		xsk_umem__delete(p->umem);
		p->umem = NULL;
	}
	lab_pool_destroy(&p->pool);
	if (p->bufs) {
		munmap(p->bufs, p->bufsize);
		p->bufs = NULL;
	}
}

static int lab_recv_port(struct lab_zc_port *port, uint32_t *lens,
			 uint64_t *addrs, int max)
{
	uint32_t idx;
	unsigned int n;
	unsigned int i;

	n = xsk_ring_cons__peek(&port->rx, (uint32_t)max, &idx);
	if (!n) {
		if (xsk_ring_prod__needs_wakeup(&port->fq))
			(void)recvfrom(xsk_socket__fd(port->xsk), NULL, 0,
				       MSG_DONTWAIT, NULL, 0);
		return 0;
	}
	for (i = 0; i < n; i++) {
		const struct xdp_desc *d =
			xsk_ring_cons__rx_desc(&port->rx, idx + i);

		addrs[i] = d->addr;
		lens[i] = d->len;
	}
	xsk_ring_cons__release(&port->rx, n);
	return (int)n;
}

int lab_recv_loc(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	return lab_recv_port(&p->loc, lens, addrs, max);
}

int lab_recv_wan(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	return lab_recv_port(&p->wan, lens, addrs, max);
}

static int lab_tx_batch(struct lab_zc_port *port, const struct lab_job *jobs,
			int n)
{
	uint32_t idx;
	uint32_t reserved;
	int i;

	if (n <= 0)
		return 0;
	reserved = xsk_ring_prod__reserve(&port->tx, (uint32_t)n, &idx);
	if (!reserved)
		return 0;
	for (i = 0; i < (int)reserved; i++) {
		struct xdp_desc *d =
			xsk_ring_prod__tx_desc(&port->tx, idx + i);

		d->addr = jobs[i].umem_addr;
		d->len = jobs[i].len;
	}
	xsk_ring_prod__submit(&port->tx, reserved);
	(void)sendto(xsk_socket__fd(port->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	return (int)reserved;
}

int lab_tx_loc_batch(struct lab_pair *p, const struct lab_job *jobs, int n)
{
	return lab_tx_batch(&p->loc, jobs, n);
}

int lab_tx_wan_batch(struct lab_pair *p, const struct lab_job *jobs, int n)
{
	return lab_tx_batch(&p->wan, jobs, n);
}

static void lab_drain_cq_port(struct lab_pair *p, struct lab_zc_port *port)
{
	uint64_t addrs[LAB_BATCH];
	uint32_t idx;
	uint32_t n;
	uint32_t i;

	n = xsk_ring_cons__peek(&port->cq, LAB_BATCH, &idx);
	if (!n)
		return;
	for (i = 0; i < n; i++)
		addrs[i] = *xsk_ring_cons__comp_addr(&port->cq, idx + i);
	xsk_ring_cons__release(&port->cq, n);
	(void)lab_pool_push(&p->pool, addrs, n);
}

void lab_drain_cq_loc(struct lab_pair *p)
{
	lab_drain_cq_port(p, &p->loc);
}

void lab_drain_cq_wan(struct lab_pair *p)
{
	lab_drain_cq_port(p, &p->wan);
}

static void lab_refill_fq_port(struct lab_pair *p, struct lab_zc_port *port)
{
	uint64_t addrs[LAB_BATCH];
	uint32_t got;
	uint32_t idx;
	uint32_t i;
	uint32_t free_slots;

	free_slots = xsk_prod_nb_free(&port->fq, LAB_BATCH);
	if (free_slots < LAB_BATCH)
		return;
	got = lab_pool_pop(&p->pool, addrs, LAB_BATCH);
	if (!got)
		return;
	if (xsk_ring_prod__reserve(&port->fq, got, &idx) != got) {
		(void)lab_pool_push(&p->pool, addrs, got);
		return;
	}
	for (i = 0; i < got; i++)
		*xsk_ring_prod__fill_addr(&port->fq, idx + i) = addrs[i];
	xsk_ring_prod__submit(&port->fq, got);
}

void lab_refill_fq_loc(struct lab_pair *p)
{
	lab_refill_fq_port(p, &p->loc);
}

void lab_refill_fq_wan(struct lab_pair *p)
{
	lab_refill_fq_port(p, &p->wan);
}
