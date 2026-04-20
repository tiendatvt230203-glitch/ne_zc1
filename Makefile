NAME := necz1
ARCH ?= $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/armv7l/arm/' -e 's/x86_64/x86/')
BPF_CLANG := clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror -Wno-unused-value

CFLAGS := -O2 -g -Wall -Wextra -I./inc -D_GNU_SOURCE
LDFLAGS := -lxdp -lbpf -lelf -lz -lpthread

OBJS := main.o src/interface.o src/threads.o
BPF_OBJS := bpf/xdp_local.o bpf/xdp_wan.o

.PHONY: all clean

all: $(NAME)

$(NAME): $(OBJS) $(BPF_OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

main.o: main.c inc/lab.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/interface.o: src/interface.c inc/lab.h
	@mkdir -p src
	$(CC) $(CFLAGS) -c -o $@ $<

src/threads.o: src/threads.c inc/lab.h inc/mac.h
	$(CC) $(CFLAGS) -c -o $@ $<

bpf/xdp_local.o: bpf/xdp_local.c
	@mkdir -p bpf
	$(BPF_CLANG) $(BPF_CFLAGS) -c -o $@ $<

bpf/xdp_wan.o: bpf/xdp_wan.c
	@mkdir -p bpf
	$(BPF_CLANG) $(BPF_CFLAGS) -c -o $@ $<

clean:
	rm -f $(NAME) $(OBJS) $(BPF_OBJS)
