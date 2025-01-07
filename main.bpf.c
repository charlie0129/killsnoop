//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// I must use licenses that are compatible with kernel source.
char __license[] SEC("license") = "GPL";

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// The max size of the bpf ring buffer.
#define RINGBUF_SIZE 1 << 24

// Max task cmdline size.
#define ARG_MAX_SIZE 256

struct event {
    __s64 source_ppid;
    __s64 source_pid;
    __s64 signal;
    __s64 target_pid;
    __s8 source_comm[TASK_COMM_LEN];
    __s8 source_cmdline[ARG_MAX_SIZE];
};

// Ring buffer to be read by the userspace program.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
    __type(value, struct event);
} events SEC(".maps");

// See: /sys/kernel/tracing/events/syscalls/sys_enter_kill/format
struct kill_params {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s32 __syscall_nr;
    __s64 pid; // Although format says it's unsigned, it is actually signed.
    __s64 signal; // Although format says it's unsigned, it is actually signed.
};

SEC("tracepoint/syscalls/sys_enter_kill")
int tp_enter_kill(struct kill_params* params)
{
#ifdef IGNORESIG0
    if (params->signal == 0) {
        return 0;
    }
#endif

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 source_pid = pid_tgid >> 32;

    // We need to get the cmdline of current task, which is in
    // curtask->mm->arg_start. See: linux/sched.h/task_struct
    struct task_struct* current_task = (struct task_struct*)bpf_get_current_task();
    if (current_task == NULL) {
        return 0;
    }

    struct mm_struct* current_mm = (struct mm_struct*)BPF_CORE_READ(current_task, mm);
    if (current_mm == NULL) {
        return 0;
    }

    const __s8* arg_start = (__s8*)BPF_CORE_READ(current_mm, arg_start);
    const __s8* arg_end = (__s8*)BPF_CORE_READ(current_mm, arg_end);
    if (arg_end <= arg_start) {
        return 0;
    }

    __u64 max_size = ARG_MAX_SIZE;
    if (arg_end - arg_start < max_size) {
        max_size = arg_end - arg_start;
    }

    // Also get the pid of the parent task, in curtask->real_parent->pid.
    struct task_struct* parent_task = (struct task_struct*)BPF_CORE_READ(current_task, real_parent);
    if (parent_task == NULL) {
        return 0;
    }

    struct event* e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e == NULL) {
        return 0;
    }

    // Reset in case ringbuffer wraps.
    e->source_ppid = 0;
    e->source_pid = 0;
    e->signal = 0;
    e->target_pid = 0;
    __builtin_memset(e->source_cmdline, (__s8)0, ARG_MAX_SIZE);
    __builtin_memset(e->source_comm, (__s8)0, TASK_COMM_LEN);

    e->source_ppid = (pid_t)BPF_CORE_READ(parent_task, pid);
    // cmdline str is in userspace. We need to copy it our bpf program.
    bpf_probe_read_user_str(e->source_cmdline, max_size, arg_start);
    bpf_get_current_comm(e->source_comm, TASK_COMM_LEN);

    e->source_pid = source_pid;
    // Although pid and signal are __u64 from tracepoints, they are actually pid_t
    // and int, so we downcast them.
    e->target_pid = (pid_t)params->pid;
    e->signal = (int)params->signal;

    bpf_ringbuf_submit(e, 0);

    return 0;
}
