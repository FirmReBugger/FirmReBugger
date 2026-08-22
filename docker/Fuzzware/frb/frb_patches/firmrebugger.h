#ifndef FIRMREBUGGER_H
#define FIRMREBUGGER_H

void firmrebugger_init_config(uc_engine *uc);
/* Reset FirmReBugger-owned state before a persistent replay. */
int firmrebugger_reset_session(uc_engine *uc);

#endif
