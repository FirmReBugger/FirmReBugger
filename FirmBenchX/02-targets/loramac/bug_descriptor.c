#include <stdint.h>
#include <tcclib.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern void frb_mem_write(uint32_t write_addr, uint32_t value);
extern void frb_report_reached(char *bug_id);
extern void frb_report_detected_triggered(char *bug_id);

static void print_reg_state(uint32_t *reg_state) {
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

typedef void (*func_ptr_t)(void);

typedef struct {
  uint32_t address;
  func_ptr_t bug_func;
} context_struct;

static void report_detected_triggered(char *bug_id) {
  frb_report_detected_triggered(bug_id);
}

static void report_reached(char *bug_id) { frb_report_reached(bug_id); }

void BUG_H18() {
  // CVE-2022-39274
  report_reached("H18");
  if (reg_state[6] == 0) {
    report_detected_triggered("H18");
  }
}

// void on_str_len(){
//     report_reached("FP_FRB24");
//     if (reg_state[3] == 0) {
//         report_detected_triggered("FP_FRB24");
//     }
// }

void on_LoRaMacCryptoHandleJoinAccept() {
  report_reached("FP_FRB25");
  if (reg_state[3] == 0) {
    report_detected_triggered("FP_FRB25");
  }
}

void on_GetLastFcntDown() {
  report_reached("FP_FRB26");
  if (reg_state[3] == 0) {
    report_detected_triggered("FP_FRB26");
  }
}

// void on_sys_dlist_remove() {
//     report_reached("FP_FRB28");
//     uint8_t free_flag = frb_mem_read(reg_state[0], 1);
//     if (free_flag == 0) {
//         report_detected_triggered("FP_FRB28");
//     }
// }

// void check_buf_struct(){
//     report_reached("FP_FRB29");
//     if (reg_state[3] < 0x08000138 || reg_state[3] > 0x0800e45d) {
//         report_detected_triggered("FP_FRB29");
//     }
// }

void mcpsidication_failed() {
  report_reached("FP_FRB31");
  report_detected_triggered("FP_FRB31");
}

context_struct context_array[] = {
    {0x08006c62, BUG_H18},
    // {0x08000bb6, on_str_len},
    {0x080085fe, on_LoRaMacCryptoHandleJoinAccept},
    {0x080081fc, on_GetLastFcntDown},
    // {0x0800ded0, on_sys_dlist_remove},
    // {0x0800bb00, check_buf_struct},
    {0x080030b2, mcpsidication_failed}};

void send_context_struct(const context_struct **arr, size_t *size) {
  *arr = context_array;
  *size = sizeof(context_array) / sizeof(context_array[0]);
}
