#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf_helpers.h>

#include "utils.h"
#include "bpf_helpers_fixer.h"

#define DATA_SIZE (2048)

struct perf_record_sample {
	u32 type;
	char arg1[DATA_SIZE];
	char arg2[DATA_SIZE];
};

struct bpf_map_def SEC("maps") perf_output = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(int),
	.max_entries = 2048,
};

struct bpf_map_def SEC("maps") tmp_storage_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct perf_record_sample),
    .max_entries = 1,
};

SEC("kprobe/bind_variable")
int bpf_prog(struct pt_regs * ctx)
{
	char * arg1 = (char *) PT_REGS_PARM1(ctx);
	char * arg2 = (char *) PT_REGS_PARM2(ctx);

	// pull out a pointer to a sample, simply because the ebpf stack is limited to 512
	// bytes so this is a good way to store big chunks of data statically. In addition,
	// the ebpf programs are not interrupted mid run, so a perf cpu array is "thread-safe".
	int map_key = 0;
	struct perf_record_sample * sample = bpf_map_lookup_elem(&tmp_storage_map, &map_key);
	if (sample == NULL) {
		println("LOG no sample");
		return 0;
	}
	sample->type = 1339;

	bpf_probe_read_str(&sample->arg1, sizeof(sample->arg1), arg1);
	bpf_probe_read_str(&sample->arg2, sizeof(sample->arg2), arg2);

	println("LOG bash_readline %u=>%u", (u64)arg1, (u64)arg2);
	bpf_perf_event_output(ctx, &perf_output, BPF_F_CURRENT_CPU,
						  sample, sizeof(struct perf_record_sample));
	return 0;
}

char _license[] SEC("license") = "GPL";
// Kernel Version of centos 7.7 (199168)
u32 _version SEC("version") = 199168;
