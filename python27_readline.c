#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf_helpers.h>

#include "utils.h"
#include "bpf_helpers_fixer.h"

#define DATA_SIZE (2048)

struct perf_record_sample {
	u32 type;
	u32 size;
	char data[DATA_SIZE];
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

SEC("kprobe/python27_readline")
int bpf_prog(struct pt_regs * ctx)
{
	char * line = (char *) PT_REGS_RC(ctx);
	if (line == NULL) {
		return 0;
	}

	// pull out a pointer to a sample, simply because the ebpf stack is limited to 512
	// bytes so this is a good way to store big chunks of data statically. In addition,
	// the ebpf programs are not interrupted mid run, so a perf cpu array is "thread-safe".
	int map_key = 0;
	struct perf_record_sample * sample = bpf_map_lookup_elem(&tmp_storage_map, &map_key);
	if (sample == NULL) {
		println("LOG no sample");
		return 0;
	}

	sample->type = 1340;
	sample->size = bpf_probe_read_str(&sample->data, sizeof(sample->data), line);
	println("LOG python2.7 readline <%d> '%s'", sample->size, &sample->data);
	bpf_perf_event_output(ctx, &perf_output, BPF_F_CURRENT_CPU,
						  sample, sizeof(struct perf_record_sample));
	return 0;
}

char _license[] SEC("license") = "GPL";
// Kernel Version of centos 7.7 (199168)
u32 _version SEC("version") = 199168;
