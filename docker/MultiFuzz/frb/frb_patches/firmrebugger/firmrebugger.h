#include <stdint.h>

typedef void* EmuData;
typedef void* Vm;

//Context Struct
typedef void (*func_ptr_t)(void);
typedef struct {
    uint32_t address;
    func_ptr_t bug_func;
} context_struct;

typedef struct CrashLoggerEmu CrashLoggerEmu;
typedef void (*firmrebugger_callback)(struct CrashLoggerEmu*, context_struct);

struct CrashLoggerEmu {
    EmuData cpu;
    uint32_t (*reg_read)(EmuData, char*);
    uint32_t (*mem_read)(EmuData, uint64_t, uint8_t*, uint32_t);
    uint32_t (*mem_write)(EmuData, uint64_t, uint8_t*, uint32_t);
    void (*add_hook)(void*, struct CrashLoggerEmu*, context_struct, firmrebugger_callback);
    void (*force_crash)(EmuData);
};

void firmrebugger_init_config(Vm, CrashLoggerEmu*);
