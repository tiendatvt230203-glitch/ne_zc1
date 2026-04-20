#include <signal.h>
#include <unistd.h>

#include "lab.h"

static struct lab_ctx g_ctx;

static void on_sig(int sig)
{
	(void)sig;
	lab_ctx_stop(&g_ctx);
}

int main(int argc, char **argv)
{
	const char *loc = "enp7s0";
	const char *wan = "enp4s0";
	const char *bpf_loc = "bpf/xdp_local.o";
	const char *bpf_wan = "bpf/xdp_wan.o";

	if (argc >= 3) {
		loc = argv[1];
		wan = argv[2];
	}

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	if (lab_run(&g_ctx, loc, wan, bpf_loc, bpf_wan))
		return 1;

	while (!g_ctx.stop)
		pause();

	lab_ctx_join(&g_ctx);
	return 0;
}
