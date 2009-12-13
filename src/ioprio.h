#include <sys/syscall.h>

enum {
	IOPRIO_CLASS_NONE,
	IOPRIO_CLASS_RT,
	IOPRIO_CLASS_BE,
	IOPRIO_CLASS_IDLE,
};

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};

#define IOPRIO_CLASS_SHIFT 13

#define IOPRIO_PRIO_VALUE(klass, data) \
	(((klass) << IOPRIO_CLASS_SHIFT) | (data))

#define IOPRIO_NORM 4

static inline int
ioprio_set (int which, int who, int ioprio) {
	return syscall (__NR_ioprio_set, which, who, ioprio);
}
