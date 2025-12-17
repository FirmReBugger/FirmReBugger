#include <tcclib.h>
#include <stdint.h>
#include <limits.h>

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

// void BUG_MF19() {
//     report_reached("MF19");
//     // 	Stdio initialization race
//     if (frb_mem_read(reg_state[3]+ 0x11c, 4) == 0x0) {
//         report_detected_triggered("MF19");
//     }
// }

int std_flag = 0;

void BUG_MF19_fin() {
    // 	Stdio initialization race
    std_flag = 1;
}

void BUG_MF19_check() {
    // 	Stdio initialization race
    report_reached("MF19");
    if (std_flag == 0) {
        report_detected_triggered("MF19");
    }
}

void BUG_MF22() {
    report_reached("MF22");
    // Issue with % encoded characters in ccnl_cs
    if (reg_state[3] == 0x25) {
        report_detected_triggered("MF22");
    }
}

void BUG_MF20() {
    // Reinitialization of shared global timer
    report_reached("MF20");
    report_detected_triggered("MF20");
}

void BUG_MF21() {
    // Missing removal from evtimer struct
    report_reached("MF21");
    report_detected_triggered("MF21");
}

void BUG_FP_MF22() {
    // Uninitialized RTC Overflow Callback
    report_reached("FP_MF22");
    if (reg_state[3] == 0x0) {
        report_detected_triggered("FP_MF22");
    }
}

context_struct context_array[] = {
    {0x00016216,BUG_MF22},
    {0x0001356c,BUG_MF20},
    {0x000168f6,BUG_MF21},
    {0x00012aa6,BUG_FP_MF22},
    {0x00012a8e,BUG_FP_MF22}, //second site for FP_MF22
    {0x00019578, BUG_MF19_fin},
    {0x00019b90, BUG_MF19_check}, //puts MF19
    {0x00019a5c, BUG_MF19_check} //printf MF19
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
