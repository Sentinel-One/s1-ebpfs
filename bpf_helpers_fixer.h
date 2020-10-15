#ifndef BPF_HELPERS_FIXER_H
#define BPF_HELPERS_FIXER_H

// in Centos-7.7 this define is missing from the bpf_helpers.h
static int (*bpf_probe_read_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 45;

#endif
