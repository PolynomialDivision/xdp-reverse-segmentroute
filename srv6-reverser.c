#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

#define IPV6_EXT_ROUTING 43
#define IPV6_ENCAP 41 // [RFC2473]

#define ipv6_optlen(p) (((p)->hdrlen + 1) << 3)

#define IPV6_RTHDR_TYPE_0	0	/* IPv6 Routing header type 0.  */

/* Routing header */
struct ip6_rthdr {
  uint8_t ip6r_nxt;     /* next header */
  uint8_t ip6r_len;     /* length in units of 8 octets */
  uint8_t ip6r_type;    /* routing type */
  uint8_t ip6r_segleft; /* segments left */
  /* followed by routing type specific data */
};

/* Type 0 Routing header */
struct ip6_rthdr0 {
  uint8_t ip6r0_nxt;      /* next header */
  uint8_t ip6r0_len;      /* length in units of 8 octets */
  uint8_t ip6r0_type;     /* always zero */
  uint8_t ip6r0_segleft;  /* segments left */
  uint8_t ip6r0_reserved; /* reserved field */
  uint8_t ip6r0_slmap[3]; /* strict/loose bit map */
  /* followed by up to 127 struct in6_addr */
  struct in6_addr ip6r0_addr[0];
};

/* Copied from glibc! Change to normal linux IPv6 header definitions! */
static inline int inet6_rth_reverse(const void *in, void *out) {
  struct ip6_rthdr *in_rthdr = (struct ip6_rthdr *)in;

  switch (in_rthdr->ip6r_type) {
    struct ip6_rthdr0 *in_rthdr0;
    struct ip6_rthdr0 *out_rthdr0;
  case IPV6_RTHDR_TYPE_0:
    in_rthdr0 = (struct ip6_rthdr0 *)in;
    out_rthdr0 = (struct ip6_rthdr0 *)out;

    /* Copy header, not the addresses.  The memory regions can overlap.  */
    __builtin_memmove(out_rthdr0, in_rthdr0, sizeof(struct ip6_rthdr0));

    int total = in_rthdr0->ip6r0_len * 8 / sizeof(struct in6_addr);
    for (int i = 0; i < total / 2; ++i) {
      /* Remember, IN_RTHDR0 and OUT_RTHDR0 might overlap.  */
      struct in6_addr temp = in_rthdr0->ip6r0_addr[i];
      out_rthdr0->ip6r0_addr[i] = in_rthdr0->ip6r0_addr[total - 1 - i];
      out_rthdr0->ip6r0_addr[total - 1 - i] = temp;
    }
    if (total % 2 != 0 && in != out)
      out_rthdr0->ip6r0_addr[total / 2] = in_rthdr0->ip6r0_addr[total / 2];

    out_rthdr0->ip6r0_segleft = total;

    return 0;
  }

  return -1;
}

struct bpf_map_def SEC("maps") segmentrouting = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct in6_addr),
    .value_size = sizeof(struct ipv6_rt_hdr),
    .max_entries = 1,
};

SEC("srv6-reverser")
int xdp_srv6_func(struct xdp_md *ctx) {
  volatile struct ethhdr old_ehdr;
  volatile struct ipv6hdr oldr_ipv6hdr;
  volatile struct ipv6hdr oldr_ipv6_orig_hdr;
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *ehdr = data;
  if (ehdr + 1 > data_end) // bounds checking
    goto out;
  old_ehdr = *ehdr;

  if (bpf_ntohs(ehdr->h_proto) != ETH_P_IPV6) {
    goto out;
  }

  // IPv6 Header
  struct ipv6hdr *ip6_srv6_hdr = (void *)(ehdr + 1);
  if (ip6_srv6_hdr + 1 > data_end)
    goto out;
  if (ip6_srv6_hdr->nexthdr != IPV6_EXT_ROUTING)
    goto out;
  oldr_ipv6hdr = *ip6_srv6_hdr;

  // Routing Header
  struct ipv6_rt_hdr *ip6_hdr = (struct ipv6_rt_hdr *)(ip6_srv6_hdr + 1);
  if (ip6_hdr + 1 > data_end)
    goto out;
  if (ip6_hdr->nexthdr != IPV6_ENCAP)
    goto out;

  // Here we need to reverse

  /* Routing header */
  // struct ip6_rthdr {
  //   uint8_t ip6r_nxt;     /* next header */
  //   uint8_t ip6r_len;     /* length in units of 8 octets */
  //   uint8_t ip6r_type;    /* routing type */
  //   uint8_t ip6r_segleft; /* segments left */
  //   /* followed by routing type specific data */
  // };

  // ToDo: Write reversed into hashmap

  // "Orig" IPv6 Header
  struct ipv6hdr *ipv6_orig_header =
      (struct ipv6hdr *)(((void *)ip6_hdr) + ipv6_optlen(ip6_hdr));
  if (ipv6_orig_header + 1 > data_end)
    goto out;
  oldr_ipv6_orig_hdr = *ipv6_orig_header;

out:
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
