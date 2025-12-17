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

void BUG_FW36() {
    report_reached("FW36");
    //Unchecked error handler in spi_init causing Null Pointer Dereference
    if (reg_state[3] == 0) {
        report_detected_triggered("FW36");
    }
}

void BUG_FW36_2() {
    report_reached("FW36");
    //Unchecked error handler in spi_init causing Null Pointer Dereference
    if (reg_state[3] == 0) {
        report_detected_triggered("FW36");
    }
}

void BUG_FP_E04() {
    report_reached("FP_E04");
    //SERCOM0 intilialization race (FP)
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_E04");
    }
}

void BUG_MF17() {
    report_reached("MF17");
    //Fragment offset is not buonds-checked in sicslowpan::input
    //Check uncomp_hdr_len + (uint16_t)(frag_offset << 3) > 
        // UIP_BUFSIZE (size stored in r0 at 0x4806 and UIP_BUFSIZE = 400).
    if (reg_state[0] > 400) {
        report_detected_triggered("MF17");
    }
}

void BUG_FP_MF18() {
    report_reached("FP_MF18");
    //(FP) Unbounded recursion when obtaining clock rate
    if (reg_state[13] > 0x2000518F || reg_state[13] < 0x20003190 ) {
        report_detected_triggered("FP_MF18");
    }
}

context_struct context_array[] = {
    {0x000012f8, BUG_FW36},
    {0x00001356, BUG_FW36_2},
    {0x000011e6, BUG_FP_E04},
    {0x00004806, BUG_MF17},
    {0x00001c06, BUG_FP_MF18}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
