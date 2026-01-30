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

void BUG_FW30() {
    report_reached("FW30");
    //Stack overflow in USB_SendString_descriptor
    uint32_t w_len = reg_state[1];
    if (w_len > 0xc000) {
        report_detected_triggered("FW30");
    }
}

void BUG_FW31() {
    report_reached("FW31");
    //strstr not checked for NULL in gsm_get_imei
    if (reg_state[0] == 0) {
        report_detected_triggered("FW31");
    }
}

void BUG_S01() {
    report_reached("S01");
    //strok not checked for NULL in gsm_get_imei
    if (reg_state[0] == 0) {
        report_detected_triggered("S01");
    }
}

void BUG_MF02() {
    report_reached("MF02");
    //strstr not checked for NULL in sms_check
    if (reg_state[5] == 0) {
        report_detected_triggered("MF02");
    }
}

void BUG_S02() {
    report_reached("S02");
    //strstr not checked for NULL in gsm_get_time
    if (reg_state[0] == 0) {
        report_detected_triggered("S02");
    }
}

void BUG_MF03() {
    report_reached("MF03");
    //strok not checked for NULL in gsm_get_time
    if (reg_state[0] == 0) {
        report_detected_triggered("MF03");
    }
}

// void strex() {
//     report_reached("strex");
//     report_detected_triggered("strex");
// }

const context_struct context_array[] = {
    {0x0008424e, BUG_FW30},
    {0x00080ae2, BUG_FW31},
    {0x00080ae8, BUG_S01},
    {0x81cf0, BUG_MF02},
    {0x00080eb4, BUG_S02},
    {0x00080ebc, BUG_MF03},
    // {0x00083f76, strex}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}


