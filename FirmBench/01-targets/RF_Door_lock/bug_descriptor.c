#include <tcclib.h>
#include <stdint.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern void frb_report_detected_triggered(char* bug_id);
extern void frb_report_reached(char* bug_id);

typedef void (*func_ptr_t)(void);

typedef struct {
    uint32_t address;
    func_ptr_t bug_func;
} context_struct;

static void report_detected_triggered(char* bug_id) {
    frb_report_detected_triggered(bug_id);
}

static void report_reached(char* bug_id) {
    frb_report_reached(bug_id);
}

void BUG_FW29() {
    report_reached("FW29");
    //Buffer overflow in set_code
    if (reg_state[4] > 15) {
        report_detected_triggered("FW29");
    }
}

void BUG_FW38() {
    // Infinite recursion in error handler
    report_reached("FW38");
    uint32_t stdio_uart_inited = frb_mem_read(0x20000f04, 4);
    if (stdio_uart_inited == 0) {
        report_detected_triggered("FW38");
    }
}


void BUG_FRB09() {
    report_reached("FRB09");
    uint32_t buffer_start = reg_state[13] - 0x20;
    uint32_t puvar4 = reg_state[4];
    int idx = puvar4 - buffer_start;
    if (idx >= 16) {
        report_detected_triggered("FRB09");
    }
}

context_struct context_array[] = {
    {0x0000044e, BUG_FW29},
    {0x00001894, BUG_FW38},
    {0x000003da, BUG_FRB09}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}

// static void print_reg_state(uint32_t *reg_state){
//     printf("Register State:\n");
//     printf("r0:  0x%08X\n", reg_state[0]);
//     printf("r1:  0x%08X\n", reg_state[1]);
//     printf("r2:  0x%08X\n", reg_state[2]);
//     printf("r3:  0x%08X\n", reg_state[3]);
//     printf("r4:  0x%08X\n", reg_state[4]);
//     printf("r5:  0x%08X\n", reg_state[5]);
//     printf("r6:  0x%08X\n", reg_state[6]);
//     printf("r7:  0x%08X\n", reg_state[7]);
//     printf("r8:  0x%08X\n", reg_state[8]);
//     printf("r9:  0x%08X\n", reg_state[9]);
//     printf("r10: 0x%08X\n", reg_state[10]);
//     printf("r11: 0x%08X\n", reg_state[11]);
//     printf("r12: 0x%08X\n", reg_state[12]);
//     printf("sp:  0x%08X\n", reg_state[13]);
//     printf("lr:  0x%08X\n", reg_state[14]);
//     printf("pc:  0x%08X\n", reg_state[15]);
// }