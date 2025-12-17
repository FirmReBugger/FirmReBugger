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

void on_lfs() {
    report_reached("FRB48");
    if (reg_state[0] == 0) {
        report_detected_triggered("FRB48");
    }
}

void on_time_utc() {
    report_reached("FRB49");
    if (reg_state[0] == 0) {
        report_detected_triggered("FRB49");
    }
}

void on_time_scet() {
    report_reached("FRB50");
    if (reg_state[0] == 0) {
        report_detected_triggered("FRB50");
    }
}

void on_time_unix() {
    report_reached("FRB51");
    if (reg_state[0] == 0) {
        report_detected_triggered("FRB51");
    }
}

void on_CO_CANtx_cb() {
    report_reached("FP_FRB53");
    if (reg_state[5] == 0) {
        report_detected_triggered("FP_FRB53");
    }
}

void on_trace_halt() {
    report_reached("FP_FRB54");
    if (reg_state[2] == 0) {
        report_detected_triggered("FP_FRB54");
    }
}

void on_vector88(){
    report_reached("FP_FRB55");
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB55");
    }
}

context_struct context_array[] = {
    {0x08016404, on_lfs},
    {0x08015ec2, on_time_utc},
    {0x08015ec2, on_time_scet},
    {0x08015e5e, on_time_unix},
    {0x0802c22a, on_CO_CANtx_cb},
    {0x08017b62, on_trace_halt},
    {0x08020742, on_vector88}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
