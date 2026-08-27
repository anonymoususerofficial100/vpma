#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>

#define TASK_COMM_LEN 32
#define MAX_PROTECTED_PIDS 64

struct security_event_t {
    u32 pid;
    u32 target_pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char event_type[32];
    u64 address;
    u64 length;
    u32 prot_flags;
    u32 blocked;
};

BPF_HASH(protected_pids, u32, u64);

BPF_HASH(authorized_debuggers, u32, u64);

BPF_HASH(text_section_start, u32, u64);
BPF_HASH(text_section_end, u32, u64);

BPF_PERF_OUTPUT(security_events);

static __always_inline int is_protected_pid(u32 pid)
{
    u64 *val = protected_pids.lookup(&pid);
    return (val != NULL);
}

static __always_inline int is_authorized_debugger(u32 pid)
{
    u64 *val = authorized_debuggers.lookup(&pid);
    return (val != NULL);
}

static __always_inline void fill_event_type(char dst[32], int type)
{
    #pragma unroll
    for (int i = 0; i < 32; i++) dst[i] = 0;

    if (type == 1) { __builtin_memcpy(dst, "PTRACE_ATTACH", 13); }
    if (type == 2) { __builtin_memcpy(dst, "PTRACE_POKETEXT", 15); }
    if (type == 3) { __builtin_memcpy(dst, "PTRACE_POKEDATA", 15); }
    if (type == 4) { __builtin_memcpy(dst, "PROC_MEM_WRITE", 14); }
    if (type == 5) { __builtin_memcpy(dst, "MPROTECT_EXEC", 13); }
    if (type == 6) { __builtin_memcpy(dst, "MMAP_EXEC_WRITE", 15); }
    if (type == 7) { __builtin_memcpy(dst, "TEXT_SECTION_MODIFY", 19); }
    if (type == 8) { __builtin_memcpy(dst, "TEXT_WRITE_ATTEMPT", 18); }
}

int syscall__trace_ptrace(struct pt_regs *ctx, long request, long pid)
{
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    u32 target_pid = (u32)pid;

    if (!is_protected_pid(target_pid))
        return 0;

    if (is_authorized_debugger(current_pid))
        return 0;

    struct security_event_t event = {};
    event.pid = current_pid;
    event.target_pid = target_pid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.blocked = 1;

    if (request == 16) {
        fill_event_type(event.event_type, 1);
    } else if (request == 4) {
        fill_event_type(event.event_type, 2);
    } else if (request == 5) {
        fill_event_type(event.event_type, 3);
    } else {
        fill_event_type(event.event_type, 1);
    }

    security_events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int kprobe__mem_write(struct pt_regs *ctx, struct file *file,
                      const char __user *buf, size_t count, loff_t *ppos)
{
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    u32 uid = bpf_get_current_uid_gid();

    if (uid == 0)
        return 0;

    struct security_event_t event = {};
    event.pid = current_pid;
    event.target_pid = 0;
    event.uid = uid;
    event.address = (u64)*ppos;
    event.length = count;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    fill_event_type(event.event_type, 4);
    event.blocked = 1;

    security_events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

static __always_inline int overlaps_text_section(u32 pid, u64 start, u64 len)
{
    u64 *text_start = text_section_start.lookup(&pid);
    u64 *text_end = text_section_end.lookup(&pid);

    if (!text_start || !text_end)
        return 0;

    u64 mprotect_end = start + len;

    if (start < *text_end && mprotect_end > *text_start)
        return 1;

    return 0;
}

int syscall__trace_mprotect(struct pt_regs *ctx, unsigned long start,
                            size_t len, unsigned long prot)
{
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_protected_pid(current_pid))
        return 0;

    int has_write = (prot & 0x2) != 0;
    int has_exec = (prot & 0x4) != 0;

    if (has_write && overlaps_text_section(current_pid, start, len)) {

        struct security_event_t event = {};
        event.pid = current_pid;
        event.target_pid = current_pid;
        event.uid = bpf_get_current_uid_gid();
        event.address = start;
        event.length = len;
        event.prot_flags = prot;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        fill_event_type(event.event_type, 7);
        event.blocked = 1;

        security_events.perf_submit(ctx, &event, sizeof(event));

        return 0;
    }

    if (has_write && has_exec) {

        struct security_event_t event = {};
        event.pid = current_pid;
        event.target_pid = current_pid;
        event.uid = bpf_get_current_uid_gid();
        event.address = start;
        event.length = len;
        event.prot_flags = prot;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        fill_event_type(event.event_type, 5);
        event.blocked = 1;

        security_events.perf_submit(ctx, &event, sizeof(event));

        return 0;
    }

    if (has_exec) {
        struct security_event_t event = {};
        event.pid = current_pid;
        event.target_pid = current_pid;
        event.uid = bpf_get_current_uid_gid();
        event.address = start;
        event.length = len;
        event.prot_flags = prot;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        fill_event_type(event.event_type, 5);
        event.blocked = 0;

        security_events.perf_submit(ctx, &event, sizeof(event));
    }

    return 0;
}

int syscall__trace_mmap(struct pt_regs *ctx, unsigned long addr,
                        unsigned long len, unsigned long prot,
                        unsigned long flags, unsigned long fd,
                        unsigned long off)
{
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_protected_pid(current_pid))
        return 0;

    int has_write = (prot & 0x2) != 0;
    int has_exec = (prot & 0x4) != 0;

    if (has_write && has_exec) {

        struct security_event_t event = {};
        event.pid = current_pid;
        event.target_pid = current_pid;
        event.uid = bpf_get_current_uid_gid();
        event.address = addr;
        event.length = len;
        event.prot_flags = prot;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        fill_event_type(event.event_type, 6);
        event.blocked = 1;

        security_events.perf_submit(ctx, &event, sizeof(event));

        return 0;
    }

    return 0;
}
