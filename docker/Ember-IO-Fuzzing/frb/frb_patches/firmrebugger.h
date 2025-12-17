#ifndef FIRMREBUGGER_H
#define FIRMREBUGGER_H
#include <stdbool.h>

#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "exec/tb-lookup.h"
#include "disas/disas.h"
#include "exec/log.h"
#include "tcg/tcg.h"

//void crash_logger_hook(CPUArchState *env, target_ulong pc_next);
void firmrebugger_init_config(CPUArchState *env,target_ulong pc_next);

#endif