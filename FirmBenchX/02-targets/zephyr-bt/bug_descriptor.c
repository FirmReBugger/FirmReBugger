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

void BUG_H29() {
    // CVE-2020-10065
    report_reached("H29");
    report_reached("FP_H52");
    uint32_t buf = reg_state[0];
    uint32_t len = reg_state[2];
    uint32_t buf_len = frb_mem_read(buf + 4, 2);
    uint32_t buf_size = frb_mem_read(buf + 6, 2);
    if (buf_len + len > buf_size) {
        if (reg_state[14] == 0x08001355){
            report_detected_triggered("H29");
        }else {
            report_detected_triggered("H52");
        }
    }
}

void BUG_H30() {
    // CVE-2020-10066
    report_reached("H30");
    if (reg_state[1] == 0) {
        report_detected_triggered("H30");
    }
}

void arch_system_halt() {
    // supposed to exit here
    report_reached("FP_FRB13");
    report_detected_triggered("FP_FRB13");
}

void on_hci_cmd_done() {
    report_reached("FP_FRB41");
    if (reg_state[1] == 0) {
        report_detected_triggered("FP_FRB41");
    }
}

context_struct context_array[] = {
    {0x0800a3d6, BUG_H29},
    {0x08002598, BUG_H30},
    {0x0800accc, arch_system_halt},
    {0x080025b8, on_hci_cmd_done}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
