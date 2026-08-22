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

uint32_t OID_END = 0x20000c10;

void on_snmp_ber_decode_string_len_header_oob() {
    report_reached("FW59");
    uint32_t input_len = reg_state[4];
    uint32_t length_octets = reg_state[5];

    if (input_len < 2 || length_octets > input_len - 2) {
        report_detected_triggered("FW59");
    }
}

void on_snmp_ber_decode_string_len_buffer_oob() {
    report_reached("FW59");
    uint32_t decoded_len = reg_state[4];
    uint32_t remaining_len = reg_state[2];

    if (decoded_len > remaining_len) {
        report_detected_triggered("FW59");
    }
}

void on_snmp_oid_decode_oid_oob() {
    report_reached("H15");
    uint32_t r2 = reg_state[2];

    if (r2 > OID_END) {
        report_detected_triggered("H15");
    }
}

void on_snmp_engine_get_bulk() {
    report_reached("H16");
    uint32_t varbinds_length_ptr = reg_state[2];
    uint32_t varbinds_length = frb_mem_read(varbinds_length_ptr,4);

    if (varbinds_length > 2) {
        report_detected_triggered("H16");
    }
}

void on_snmp_oid_copy_oob() {
    report_reached("H17");
    // At the source load r4 is the current zero-based copy index. All callers
    // in this firmware use 16-word OID arrays, so index 16 is the first invalid
    // read and necessarily precedes the corresponding out-of-bounds write.
    uint32_t OID_ARR_SIZE = 16;
    uint32_t current_index = reg_state[4];

    if (current_index >= OID_ARR_SIZE) {
        report_detected_triggered("H17");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x002088ce, on_snmp_oid_decode_oid_oob);
    frb_add_reflection_point(0x00208ae6, on_snmp_ber_decode_string_len_header_oob);
    frb_add_reflection_point(0x00208b22, on_snmp_ber_decode_string_len_buffer_oob);
    frb_add_reflection_point(0x00208bd2, on_snmp_engine_get_bulk);
    frb_add_reflection_point(0x00208926, on_snmp_oid_copy_oob);
}
