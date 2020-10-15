#ifndef UTILS_H
#define UTILS_H

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#ifdef DEBUG
#define print(fmt, ...) ({char buffer[] = fmt; bpf_trace_printk(buffer, sizeof(buffer), ##__VA_ARGS__);})
#define println(fmt, ...) (print(fmt "\n", ##__VA_ARGS__))
#else
#define print(fmt, ...) (void)0
#define println(fmt, ...) (void)0
#endif


#endif
