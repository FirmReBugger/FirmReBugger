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

void FRB38() {
    report_reached("FRB38");
    uint32_t addr_ptr = reg_state[2];
    if (frb_mem_read(addr_ptr,4) == 0) {
        //*addr == NULL
        report_detected_triggered("FRB38");
    }
}

void FRB39() {
    report_reached("FRB39");
    if (reg_state[14] == 0) {
        // newMsg->code == NULL
        report_detected_triggered("FRB39");
    }
}

void test() {
    report_reached("FRB46");
    if (reg_state[3] == 0) {
        report_detected_triggered("FRB46");
    }
}

void on_protocol_process_ReadValue() {
    report_reached("FP_FRB52");
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB52");
    }
}

context_struct context_array[] = {
    {0x08009494, FRB38},
    {0x08006f36, FRB39},
    {0x080094b4, test},
    {0x08006f40, on_protocol_process_ReadValue}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
