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

void on_cliled() {
    report_reached("FRB52");
    if (reg_state[3] == 0) {
        report_detected_triggered("FRB52");
    }
}

void on_clihelp() {
    report_reached("FRB53");
    uint32_t ptr = reg_state[0];
    if (frb_mem_read(ptr, 4) == 0) {
        report_detected_triggered("FRB53")
    }
}

void on_clicolor() {
    report_reached("FRB54");
    uint32_t ptr = reg_state[0];
    if (frb_mem_read(ptr, 4) == 0) {
        report_detected_triggered("FRB54");
    }
}

void on_cligps() {
    report_reached("FRB55");
    if (reg_state[1] == 0) {
        report_detected_triggered("FRB55");
    }
}

void on_cliaux() {
    report_reached("FRB56");
    uint32_t ptr = reg_state[7];
    if (frb_mem_read(ptr, 4) == 0) {
        report_detected_triggered("FRB56");
    }
}

context_struct context_array[] = {
    {0x08015efe, on_cliled},
    {0x08017820, on_clihelp},
    {0x08015f86, on_clicolor},
    {0x0804c6c6, on_cligps},
    {0x08015432, on_cliaux}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
