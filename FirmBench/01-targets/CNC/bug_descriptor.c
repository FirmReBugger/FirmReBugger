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

void BUG_FW11() {
    report_reached("FW11");
    //Stack buffer Overflow in printFloat
    if (reg_state[2] > 9) {
        report_detected_triggered("FW11");
    }
}

void  BUG_FW18() {
    report_reached("FW18");
    //Validation issue in planner_recalculate_trapezoids
    if (reg_state[3] == 0) {
        report_detected_triggered("FW18");
    }
}

void BUG_FP_E02() {
    report_reached("FP_E02");
    // (FP) Data race in st_cycle_reinitialize
    if (frb_mem_read(0x20000e38,4) == 0) {
        report_detected_triggered("FP_E02");
    }
}

context_struct context_array[] = {
    {0x08004f8a, BUG_FW11},
    {0x08002f28, BUG_FW18},
    {0x08005856, BUG_FP_E02}
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