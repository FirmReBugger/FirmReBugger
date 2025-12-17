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

static void print_reg_state(uint32_t *reg_state){
    printf("Register State:\n");
    printf("r0:  0x%08X\n", reg_state[0]);
    printf("r1:  0x%08X\n", reg_state[1]);
    printf("r2:  0x%08X\n", reg_state[2]);
    printf("r3:  0x%08X\n", reg_state[3]);
    printf("r4:  0x%08X\n", reg_state[4]);
    printf("r5:  0x%08X\n", reg_state[5]);
    printf("r6:  0x%08X\n", reg_state[6]);
    printf("r7:  0x%08X\n", reg_state[7]);
    printf("r8:  0x%08X\n", reg_state[8]);
    printf("r9:  0x%08X\n", reg_state[9]);
    printf("r10: 0x%08X\n", reg_state[10]);
    printf("r11: 0x%08X\n", reg_state[11]);
    printf("r12: 0x%08X\n", reg_state[12]);
    printf("sp:  0x%08X\n", reg_state[13]);
    printf("lr:  0x%08X\n", reg_state[14]);
    printf("pc:  0x%08X\n", reg_state[15]);
}

static void report_detected_triggered(char* bug_id) {
    frb_report_detected_triggered(bug_id);
}

static void report_reached(char* bug_id) {
    frb_report_reached(bug_id);
}

void BUG_FP_FW27() {
    report_reached("FP_FW27");
    //(FP) Buffer overflow in fnExtractFIFO
    if (reg_state[3] > 64) {
        report_detected_triggered("FP_FW27");
    }
}

void  BUG_FP_FW45() {
    report_reached("FP_FW45");
    //(FP) Out-of-bounds access in fnUSB_handle_frame from GRXSTSPR.CHNUM value
    if (reg_state[2] > 1) {
        report_detected_triggered("FP_FW45");
    }
}

void BUG_MF04() {
    report_reached("MF04");
    // Out-of-bounds access from interface index in control_callback
    if (reg_state[1] > 1) {
        report_detected_triggered("MF04");
    }
}

void BUG_FP_MF05() {
    report_reached("FP_MF05");
    // (FP) Uninitialized usage of SerialHandle
    if (frb_mem_read(0x20000948,1) == 0) {
        report_detected_triggered("FP_MF05");
    }
    if (frb_mem_read(0x20000948 + 1,1) == 0) {
        report_detected_triggered("FP_MF05");
    }
}

void BUG_S04() {
    report_reached("S04");
    // Direct manipulation of memory using I/O menu
    if (reg_state[1] > 1) {
        report_detected_triggered("S04");
    }
}

void BUG_FP_FRB06() {
    // (FP) fnRead 
    report_reached("FP_FRB06");
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FRB06");
    }
}

void BUG_FP_FRB07() {
    // (FP) fnMsgs
    report_reached("FP_FRB07");
    if (reg_state[4] == 0) {
        report_detected_triggered("FP_FRB07");
    }
}

void BUG_FP_FRB08() {
    // (FP) fndriver 
    report_reached("FP_FRB08");
    if (reg_state[0] == 0) {
        report_detected_triggered("FP_FRB08");
    }
}


context_struct context_array[] = {
    {0x800d65e, BUG_FP_FW27}, //FW27
    {0x800fc2c, BUG_FP_FW45}, //FW45
    {0x8011c10, BUG_MF04},
    {0x800f0c2, BUG_FP_MF05},
    {0x800efea, BUG_FP_MF05},
    {0x080127c4, BUG_S04},
    {0x0800f29c, BUG_FP_FRB06},
    {0x800f2d4, BUG_FP_FRB07},
    {0x0800f1f2, BUG_FP_FRB08}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}

