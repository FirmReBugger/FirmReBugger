#include <tcclib.h>
#include <stdint.h>
#include <stdbool.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern void frb_mem_write(uint32_t write_addr, uint32_t write_value, size_t size);
extern void frb_report_detected_triggered(const char* bug_id);
extern void frb_report_reached(const char* bug_id);
extern uint32_t frb_symbolize(const char *symbol_name, uint32_t offset);
extern void frb_add_reflection_point(uint32_t address, void (*introspection_point)(void));
extern void frb_print_regs(void);

static void report_detected_triggered(const char* bug_id) {
    frb_report_detected_triggered(bug_id);
}

static void report_reached(const char* bug_id) {
    frb_report_reached(bug_id);
}


void BUG_H18() {
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
  report_reached("FP_FRB58");
  report_detected_triggered("FP_FRB58");
}

void spi_trans_failed() {
  report_reached("FP_FRB40");
  report_detected_triggered("FP_FRB40");
}

void register_reflection_points() {
    frb_add_reflection_point(0x08006c62, BUG_H18);
    frb_add_reflection_point(0x080085fe, on_LoRaMacCryptoHandleJoinAccept);
    frb_add_reflection_point(0x080081fc, on_GetLastFcntDown);
    frb_add_reflection_point(0x080030b2, mcpsidication_failed);
    frb_add_reflection_point(0x08003dcc, spi_trans_failed);
}
