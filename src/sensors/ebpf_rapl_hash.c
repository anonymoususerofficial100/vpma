#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_RAPL_ENTRIES 64

struct rapl_reading {
    u64 energy_uj;
    u64 timestamp_ns;
    u32 socket_id;
    u32 domain_id;
    u64 hash;
    u8 valid;
    u8 padding[7];
};

BPF_ARRAY(rapl_hash_map, struct rapl_reading, MAX_RAPL_ENTRIES);

BPF_ARRAY(compute_control, u32, 1);

#define SIPTAG_PRODUCER_RAPL_SEEDED 1u
#define SIPTAG_PRODUCER_RAPL_KERNEL 2u

#define SIPTAG_K0 0xSIPTAG_K0_PLACEHOLDERULL
#define SIPTAG_K1 0xSIPTAG_K1_PLACEHOLDERULL
#define SIPTAG_EPOCH SIPTAG_EPOCH_PLACEHOLDERu

#define SIPTAG_VERSION 1u

#define SIPTAG_LEN_BLOCK 0x2000000000000000ULL

static __always_inline u64 siptag_rotl(u64 x, int b) {
    return (x << b) | (x >> (64 - b));
}

#define SIPROUND(v0, v1, v2, v3) do {                       \
    v0 += v1; v1 = siptag_rotl(v1, 13); v1 ^= v0; v0 = siptag_rotl(v0, 32); \
    v2 += v3; v3 = siptag_rotl(v3, 16); v3 ^= v2;           \
    v0 += v3; v3 = siptag_rotl(v3, 21); v3 ^= v0;           \
    v2 += v1; v1 = siptag_rotl(v1, 17); v1 ^= v2; v2 = siptag_rotl(v2, 32); \
} while (0)

#define SIPABSORB(v0, v1, v2, v3, m) do {                   \
    v3 ^= (m); SIPROUND(v0, v1, v2, v3); SIPROUND(v0, v1, v2, v3); v0 ^= (m); \
} while (0)

static __always_inline u64 siptag(u64 energy_uj, u64 timestamp_ns,
                                  u32 unit_id, u32 domain_id,
                                  u16 version, u16 producer, u32 key_epoch) {
    u64 v0 = 0x736f6d6570736575ULL ^ SIPTAG_K0;
    u64 v1 = 0x646f72616e646f6dULL ^ SIPTAG_K1;
    u64 v2 = 0x6c7967656e657261ULL ^ SIPTAG_K0;
    u64 v3 = 0x7465646279746573ULL ^ SIPTAG_K1;

    u64 m2 = ((u64)unit_id) | (((u64)domain_id) << 32);
    u64 m3 = ((u64)version) | (((u64)producer) << 16) | (((u64)key_epoch) << 32);

    SIPABSORB(v0, v1, v2, v3, energy_uj);
    SIPABSORB(v0, v1, v2, v3, timestamp_ns);
    SIPABSORB(v0, v1, v2, v3, m2);
    SIPABSORB(v0, v1, v2, v3, m3);
    SIPABSORB(v0, v1, v2, v3, SIPTAG_LEN_BLOCK);

    v2 ^= 0xffULL;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

int auto_compute_hash(struct pt_regs *ctx) {

    u32 idx;
    struct rapl_reading *reading;

    idx = 0;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = siptag(reading->energy_uj, reading->timestamp_ns,
                               reading->socket_id, reading->domain_id,
                               SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_SEEDED, SIPTAG_EPOCH);
        reading->valid = 1;
    }

    idx = 1;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = siptag(reading->energy_uj, reading->timestamp_ns,
                               reading->socket_id, reading->domain_id,
                               SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_SEEDED, SIPTAG_EPOCH);
        reading->valid = 1;
    }

    idx = 2;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = siptag(reading->energy_uj, reading->timestamp_ns,
                               reading->socket_id, reading->domain_id,
                               SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_SEEDED, SIPTAG_EPOCH);
        reading->valid = 1;
    }

    idx = 3;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = siptag(reading->energy_uj, reading->timestamp_ns,
                               reading->socket_id, reading->domain_id,
                               SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_SEEDED, SIPTAG_EPOCH);
        reading->valid = 1;
    }

    idx = 4;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = siptag(reading->energy_uj, reading->timestamp_ns,
                               reading->socket_id, reading->domain_id,
                               SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_SEEDED, SIPTAG_EPOCH);
        reading->valid = 1;
    }

    idx = 5;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = siptag(reading->energy_uj, reading->timestamp_ns,
                               reading->socket_id, reading->domain_id,
                               SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_SEEDED, SIPTAG_EPOCH);
        reading->valid = 1;
    }

    idx = 6;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = siptag(reading->energy_uj, reading->timestamp_ns,
                               reading->socket_id, reading->domain_id,
                               SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_SEEDED, SIPTAG_EPOCH);
        reading->valid = 1;
    }

    idx = 7;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = siptag(reading->energy_uj, reading->timestamp_ns,
                               reading->socket_id, reading->domain_id,
                               SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_SEEDED, SIPTAG_EPOCH);
        reading->valid = 1;
    }

    return 0;
}

BPF_HASH(rapl_kernel_scratch, u64, u64);

BPF_HASH(rapl_ctx_hint, u64, u64);

int trace_rapl_read_entry(struct pt_regs *ctx) {
    u64 prim  = (u64)PT_REGS_PARM2(ctx);
    u64 xlate = (u64)PT_REGS_PARM3(ctx);
    if (prim != 0 || xlate == 0)
        return 0;
    u64 data_ptr = (u64)PT_REGS_PARM4(ctx);
    if (data_ptr == 0)
        return 0;
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    rapl_kernel_scratch.update(&tgid, &data_ptr);

    u64 *hint = rapl_ctx_hint.lookup(&tgid);
    if (hint) {
        u32 socket_id = (u32)(*hint >> 32);
        u32 domain_id = (u32)(*hint & 0xffffffff);
        if (socket_id < MAX_RAPL_ENTRIES && domain_id < 4) {
            u32 idx = socket_id * 4 + domain_id;
            if (idx < MAX_RAPL_ENTRIES) {
                struct rapl_reading *r = rapl_hash_map.lookup(&idx);
                if (r)
                    r->valid = 0;
            }
        }
    }
    return 0;
}

int trace_rapl_read_ret(struct pt_regs *ctx) {
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    u64 *data_ptr = rapl_kernel_scratch.lookup(&tgid);
    if (!data_ptr)
        return 0;

    u64 *hint = rapl_ctx_hint.lookup(&tgid);
    if (hint) {

        int rc = (int)PT_REGS_RC(ctx);
        if (rc == 0) {
            u32 socket_id = (u32)(*hint >> 32);
            u32 domain_id = (u32)(*hint & 0xffffffff);

            if (socket_id < MAX_RAPL_ENTRIES && domain_id < 4) {
                u64 energy_uj = 0;
                long pr = bpf_probe_read_kernel(&energy_uj, sizeof(energy_uj), (void *)*data_ptr);
                u32 idx = socket_id * 4 + domain_id;
                if (pr == 0 && energy_uj != 0 && idx < MAX_RAPL_ENTRIES) {
                    struct rapl_reading *r = rapl_hash_map.lookup(&idx);
                    if (r) {
                        r->energy_uj = energy_uj;
                        r->timestamp_ns = bpf_ktime_get_ns();
                        r->socket_id = socket_id;
                        r->domain_id = domain_id;

                        r->hash = siptag(energy_uj, r->timestamp_ns, socket_id, domain_id,
                                         SIPTAG_VERSION, SIPTAG_PRODUCER_RAPL_KERNEL, SIPTAG_EPOCH);
                        r->valid = 1;
                    }
                }
            }
        }
        rapl_ctx_hint.delete(&tgid);
    }
    rapl_kernel_scratch.delete(&tgid);
    return 0;
}
