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

void on_CVE_2020_10064() {
    report_reached("H58");
    uint32_t lr = reg_state[14];
    print_reg_state(reg_state);

    if (reg_state[2] > 0xf0000000 && lr == 0x00407987) {
        report_detected_triggered("H58");
    } 
}

void on_CVE_2021_3320() {
    report_reached("H56");
    if (reg_state[3] == 2) {
        report_detected_triggered("H56");
    }
}

void on_CVE_2021_3322() {
    report_reached("H53");
    uint32_t frags = frb_mem_read(reg_state[0] + 0x10, 4);
    if (frags == 0) {
        report_detected_triggered("H53");
    }
}

void on_CVE_2021_3321() {
    // Check for size underflow in memmove call from ieee802154_reassemble
    report_reached("H55");
    if (reg_state[2] > 0xf0000000 && reg_state[14] == 0x00403c78) {
        report_detected_triggered("H55");
    }
}

void on_z_handle_obj_poll_events() {
    report_reached("FP_FRB30");
    if (reg_state[0] == 0) {
        report_detected_triggered("FP_FRB30");
    }
}

void on_fragment_remove_headers() {
    report_reached("H59");
    uint32_t ptr = reg_state[5];
    uint32_t buf_len = frb_mem_read(ptr + 0xc, 2);
    uint32_t datagram_type = frb_mem_read(ptr + 8, 1);
    int hdr_len = 0;

    if (datagram_type & 0xf8 == 0xc0) {
        hdr_len = 4;
    }else {
        hdr_len = 5;
    }

    if (buf_len < hdr_len) {
        report_detected_triggered("H59");
    } 
}

void on_net_if_config_ipv6_get() {
    report_reached("H60");
    if (reg_state[0] == 0) {
        report_detected_triggered("H60");
    }
}

void on_net_if_ipv6_calc_reachable_time() {
    report_reached("H61");
    if (reg_state[0] == 0) {
        report_detected_triggered("H61");
    } 
}

void on_z_work_q_main() {
    report_reached("FP_FRB18");
    if (reg_state[2] == 0) {
        report_detected_triggered("FP_FRB18");
    }
}

void on_remove_timeout() {
    report_reached("FP_FRB19");
    if (reg_state[2] == 0 || reg_state[3] == 0) {
        report_detected_triggered("FP_FRB19");
    }
}

context_struct context_array[] = {
    {0x0040daba, on_CVE_2020_10064},
    {0x0040dfa4, on_CVE_2021_3320},
    {0x00407918, on_CVE_2021_3322},
    {0x00404826, on_fragment_remove_headers},
    {0x004051c0, on_net_if_config_ipv6_get},
    {0x0040e76c, on_net_if_ipv6_calc_reachable_time},
    {0x0040daba, on_CVE_2021_3321},
    {0x004112fe, on_z_handle_obj_poll_events},
    {0x0040bf28, on_z_work_q_main},
    {0x0040ba2c, on_remove_timeout}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
