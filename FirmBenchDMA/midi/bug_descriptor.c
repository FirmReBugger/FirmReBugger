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

void on_MIDI_note_off_do() {
    report_reached("DI4");
    report_detected_triggered("DI4");
}

void on_MIDI_note_on_do() {
    report_reached("DI5");
    report_detected_triggered("DI5");
}

void register_reflection_points() {
    frb_add_reflection_point(0x080015d8, on_MIDI_note_off_do);
    frb_add_reflection_point(0x08001590, on_MIDI_note_on_do);
}
