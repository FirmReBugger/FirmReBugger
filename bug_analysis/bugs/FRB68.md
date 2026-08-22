---
bug_id: FRB68
binary: riot_gnrc_networking
mcu: CC2538NF53
cwes: [CWE-125, CWE-476]
benchmarks: [FirmBench]
status: confirmed
summary: The `6ctx del` shell branch consumes argv[2] without requiring a context-ID argument, passing an invalid pointer to atoi.
---

# Bug Description

The `_gnrc_6ctx` shell handler checks only that two arguments are present before dispatching its subcommands. Its `add` branch performs an additional count check, but the `del` branch calls `_gnrc_6ctx_del(argv[0], argv[2])` without requiring a third argument.

The valid but incomplete command `6ctx del` therefore reads beyond the supplied argument list. The slot may contain NULL or stale stack data. `_gnrc_6ctx_del` passes that value to `atoi`, whose numeric parser dereferences it as a string pointer.

The delete branch must require `argc >= 3` before loading `argv[2]` and should reject a missing or malformed context identifier with a usage error. It must not rely on the contents of argument slots beyond `argv[argc - 1]`.
