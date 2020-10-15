#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <linux/perf_event.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <bpf_helpers.h>

#include "bpf_helpers_fixer.h"
#include "utils.h"

#define SMB_PORT1 (445)
#define SMB_PORT2 (139)

#define SMB_TREE_CONNECT_ANDX (0x75)
#define SMB_TREE_CONNECT (0x3)

/* IP protocol defines */
#define IP_PROTOCOL_TCP    0x6
#define IP_PROTOCOL_UDP    0x11

#define DATA_SIZE (128) // MUST BE A POWER OF 2!!!

#define SMB1_VER (0xff)
#define SMB2_VER (0xfe)

struct smb_pre_header
{
	u8  NetbiosHeader[4];
	u8  Protocol_ver;
	u8  Protocol[3];
} __attribute__((packed));

struct smb1_hdr
{
	struct smb_pre_header hdr;
	u8  Command;
	u32 Status;
	u8  Flags;
	u16 Flags2;
	u16 PIDHigh;
	u8  SecurityFeatures[8];
	u16 Reserved;
	u16 TID;
	u16 PIDLow;
	u16 UID;
	u16 MID;
} __attribute__((packed));

struct smb2_hdr
{
	struct smb_pre_header hdr;
	u16 HeaderLength;
	u16 CreditCharge;
	u16 ChannelSequence;
	u16 Reserved;
	u16 Command;
	u16 CreditRequested;
	u32 Flags; // This is a bitfield
	u32 ChainOffset;
	u64 MessageID;
	u32 ProcessID;
	u32 TreeID;
	u64 SessionID;
	char Signature[16];
} __attribute__((packed));

struct perf_record_sample {
	u32 type;
	u32 size;
	char data[DATA_SIZE];
};

struct tracepoint_data
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	void * skbaddr;
	unsigned int len;
	int rc;
	char name[];
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

static inline u16 be_to_le(u16 data)
{
	return ((data & 0xff) << 8) | ((data & 0xff00) >> 8);
}

static int send_perf_data(struct tracepoint_data * tp_data, unsigned char * data_ptr, unsigned int len)
{
	// pull out a pointer to a sample, simply because the ebpf stack is limited to 512
	// bytes so this is a good way to store big chunks of data statically. In addition,
	// the ebpf programs are not interrupted mid run, so a perf cpu array is "thread-safe".
	int map_key = 0;
	struct perf_record_sample * sample = bpf_map_lookup_elem(&tmp_storage_map, &map_key);
	if (sample == NULL) {
		println("LOG no sample");
		return 0;
	}

	unsigned int extra_data_len = sizeof(sample->data);
	if (len < sizeof(sample->data)) {
		/*
			This is a so called hack, referred to in
			https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/
			although this bitwise `and` is meaningless because `len` is smaller than `sizeof(buffer)`,
			and because `sizeof(buffer) - 1` is of the form 0b0111111...1
			it helps the verifier see that `len` cant be bigger than sizeof(buffer) and cant be negative.
			NOTE: the if `sizeof(buffer)` is not a power of 2, this would not work,
			it works essentially because it preserves the lower bits of `len` (len & 0b011111111)
		*/
		extra_data_len = (len) & (sizeof(sample->data) - 1);
	}

	int res = bpf_probe_read(&sample->data, extra_data_len, data_ptr);
	if (res != 0) {
		println("LOG Failed to read extra data %d", res);
		return 0;
	}

	sample->size = extra_data_len;
	sample->type = 1337;

	println("LOG Sending Perf event of smb connect<%d>", extra_data_len);
	/* emit event */
	bpf_perf_event_output(tp_data, &perf_output, BPF_F_CURRENT_CPU,
			      		  sample, sizeof(struct perf_record_sample));
	return 0;
}

static int extract_tcp_payload(struct tracepoint_data * tp_data, unsigned char ** data, unsigned int * len)
{
	struct tcphdr hdr = {};
	struct sk_buff * skb = (struct sk_buff *) tp_data->skbaddr;
	unsigned char * buffer_base_ptr = _(skb->head);
	char * tcp_hdr_ptr = buffer_base_ptr + _(skb->transport_header);
	bpf_probe_read(&hdr, sizeof(hdr), tcp_hdr_ptr);
	unsigned char * data_start = tcp_hdr_ptr + hdr.doff * 4;
	unsigned char * data_end = buffer_base_ptr + _(skb->tail);
	int data_left = data_end - data_start;
	*data = data_start;
	*len = data_left;
	return 0;
}

static int handle_payload(struct tracepoint_data * tp_data, unsigned char * data, unsigned int len)
{
	struct smb_pre_header pre_header = {};
	if (len <= sizeof(struct smb_pre_header)) {
		println("LOG Data left is too small: %d", len);
		return 0;
	}
	bpf_probe_read(&pre_header, sizeof(pre_header), data);

	if (pre_header.Protocol[0] != 'S' || pre_header.Protocol[1] != 'M' || pre_header.Protocol[2] != 'B') {
		println("LOG Invalid protocol");
		return 0;
	}


	u8 command;
	unsigned header_size;
	// handle both smb1 and smb2
	if (pre_header.Protocol_ver == SMB1_VER) {
		struct smb1_hdr smb_hdr = {};
		if (len <= sizeof(struct smb1_hdr)) {
			println("LOG smb1, data left too small");
			return 0;
		}
		bpf_probe_read(&smb_hdr, sizeof(smb_hdr), data);
		command = smb_hdr.Command;
		header_size = sizeof(struct smb1_hdr);
		println("LOG found smb1 version");
	} else if (pre_header.Protocol_ver == SMB2_VER) {
		struct smb2_hdr smb_hdr = {};
		if (len <= sizeof(struct smb2_hdr)) {
			println("LOG smb2, data left too small");
			return 0;
		}
		bpf_probe_read(&smb_hdr, sizeof(smb_hdr), data);
		command = smb_hdr.Command;
		header_size = sizeof(struct smb2_hdr);
		println("LOG found smb2 version");
	} else {
		println("LOG unknown version %u", pre_header.Protocol_ver);
		return 0;
	}

	// validate this is a connect command
	if (command != SMB_TREE_CONNECT_ANDX && command != SMB_TREE_CONNECT) {
		println("LOG Not an SMBTreeConectANDX command %d", command);
		return 0;
	}

	send_perf_data(tp_data, data + header_size, len - header_size);
	println("LOG passed");
	return 0;
}

SEC("tracepoint/net_dev_xmit")
int bpf_prog1(struct tracepoint_data * tp_data)
{
	struct sk_buff * skb = (struct sk_buff *) tp_data->skbaddr;
	struct sock * sock = _(skb->sk);
	u16 be_dport = _(sock->__sk_common.skc_dport);
	u16 dport = be_to_le(be_dport);
	u16 sport = _(sock->__sk_common.skc_num);

	// validate the dport is smb
	if (dport != SMB_PORT1 && dport != SMB_PORT2) {
		return 0;
	}

	u16 eth_protocol = _(skb->protocol);
	if (be_to_le(eth_protocol) != ETH_P_IP) {
		println("LOG invalid ethernet type %u", eth_protocol);
		return 0;
	}

	struct iphdr * ip_hdr = (struct iphdr *)(_(skb->head) + _(skb->network_header));

	u8 * version_ptr = (u8 *)ip_hdr;
	// we read the first byte which is version | ihl (ip header length)
	u8 version_ihl = _(*version_ptr);
	u8 version = (version_ihl & 0xf0) >> 4;
	u8 ihl = version_ihl & 0xf;
	u8 ip_protocol = _(ip_hdr->protocol);

	// sanity make sure its ipv4
	if (version != 0x4) {
		return 0;
	}

	unsigned char * data;
	unsigned int length;
	if (ip_protocol == IP_PROTOCOL_TCP) {
		extract_tcp_payload(tp_data, &data, &length);
		println("LOG Payload extracted!");
	} else if (ip_protocol == IP_PROTOCOL_UDP) {
		println("LOG UDP passed! %u", 1);
	} else {
		println("LOG failed to determine protocol");
		return 0;
	}

	return handle_payload(tp_data, data, length);
}

char _license[] SEC("license") = "GPL";
// Kernel Version of centos 7.7 (199168)
u32 _version SEC("version") = 199168;
