# POSIX-port FreeRTOS op-sequence fuzzer, built with the shared oracle in core/.

# KERNEL: FreeRTOS-Kernel checkout; run_fuzzer.sh's FREERTOS_KERNEL also works.
KERNEL ?= $(FREERTOS_KERNEL)
ifeq ($(strip $(KERNEL)),)
KERNEL := /tmp/FreeRTOS-Kernel
endif
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(wildcard $(KERNEL)/tasks.c),)
$(error FreeRTOS-Kernel not found at "$(KERNEL)". Set FREERTOS_KERNEL=/path/to/FreeRTOS-Kernel (the same variable freertos/run_fuzzer.sh uses), or pass KERNEL=... to make)
endif
endif
CORE_DIR = ../../core
# SANITIZE=1 adds ASAN; run with ASAN_OPTIONS=use_sigaltstack=0 (run-all does).
SANFLAGS =
ifeq ($(SANITIZE),1)
SANFLAGS = -fsanitize=address
endif
CFLAGS = -O0 -g $(SANFLAGS) -fno-omit-frame-pointer \
         -I. -I$(CORE_DIR) -I$(KERNEL)/include -I$(KERNEL) \
         -I$(KERNEL)/portable/ThirdParty/GCC/Posix \
         -I$(KERNEL)/portable/ThirdParty/GCC/Posix/utils
# queue.c is built through fr_queue_shim.c, which #includes it; do not add it.
SRCS_KERNEL = $(KERNEL)/tasks.c fr_queue_shim.c $(KERNEL)/list.c \
              $(KERNEL)/timers.c $(KERNEL)/event_groups.c \
              $(KERNEL)/stream_buffer.c \
              $(KERNEL)/portable/MemMang/heap_3.c \
              $(KERNEL)/portable/ThirdParty/GCC/Posix/port.c \
              $(KERNEL)/portable/ThirdParty/GCC/Posix/utils/wait_for_event.c

SRCS_ORACLE = $(CORE_DIR)/op_ir.c $(CORE_DIR)/fuzz_core.c $(CORE_DIR)/sigma_rt.c \
              $(CORE_DIR)/structural_inv.c \
              $(CORE_DIR)/wait_q_oracle.c \
              $(CORE_DIR)/invariants.c $(CORE_DIR)/rt_invariants.c \
              freertos_posix_adapter.c

HDRS = FreeRTOSConfig.h freertos_posix_adapter.h \
       $(addprefix $(CORE_DIR)/,coverage.h fuzz_core.h invariants.h op_ir.h \
           rt_invariants.h rt_model.h sigma_rt.h structural_inv.h wait_q_oracle.h)

TARGETS = fuzz_opseq

all: $(TARGETS)

# Records the SANITIZE flavour, so switching it rebuilds the binary.
FLAVOR_STAMP = .build-flavor
$(FLAVOR_STAMP): FORCE
	@echo 'SANITIZE=$(SANITIZE)' | cmp -s - $@ || echo 'SANITIZE=$(SANITIZE)' > $@
FORCE:
.PHONY: FORCE all run-all clean

$(TARGETS): %: %.c $(SRCS_ORACLE) $(SRCS_KERNEL) $(HDRS) $(FLAVOR_STAMP)
	gcc $(CFLAGS) $(filter %.c,$^) -lpthread -o $@

run-all: $(TARGETS)
	@for t in $(TARGETS); do echo "=== $$t ==="; \
	    ASAN_OPTIONS=use_sigaltstack=0:detect_leaks=0 ./$$t; echo; done

clean:
	rm -f $(TARGETS) $(FLAVOR_STAMP)
