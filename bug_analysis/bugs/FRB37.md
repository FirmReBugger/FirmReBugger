---
bug_id: FRB37
binary: riot_gnrc_networking
mcu: CC2538NF53
cwes: [CWE-20, CWE-476]
benchmarks: [FirmBench]
status: confirmed
summary: A non-abort SFR first fragment can declare a zero datagram size, causing IPHC receive to clear and then dereference the IPv6 snippet data pointer.
---

# Bug Description

The 6LoWPAN Selective Fragment Recovery parser treats a first fragment with both datagram size and fragment size equal to zero as an abort marker. It does not reject the inconsistent form where the declared datagram size is zero but the fragment still contains payload, and it creates reassembly state with `datagram_size == 0`.

`gnrc_sixlowpan_iphc_recv` later uses that datagram size as the requested size for `gnrc_pktbuf_realloc_data`. Resizing an existing IPv6 snippet to zero releases its data allocation and stores NULL in the snippet while reporting successful completion.

The caller assumes the resized snippet still contains an IPv6 header and writes fields such as `ipv6_hdr->len` through the NULL data pointer. The parser must either recognize only the exact empty abort form or reject every non-abort fragment whose declared datagram size is zero before allocating reassembly state.
