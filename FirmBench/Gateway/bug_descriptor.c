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


void BUG_FW12() {
    report_reached("FW12");
    // User provided pin argument is not bounds checked
    if (reg_state[1] >= 60) {
        report_detected_triggered("FW12");
    }
}

void BUG_FP_FW21() {
    report_reached("FP_FW21");
    // (FP) initialization race in HAL_UART_TxCpltCallback
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FW21");
    }
}

void BUG_FP_FW22() {
    report_reached("FP_FW22");
    // (FP) Uninitialized use of hi2c->pBuffPtr in I2C_ITError
    // FIXED 2026-07-15: this reflection point used to also be registered at
    // 0x080050da (inside I2C_Slave_STOPF, checking hi2c->hdmarx==NULL) --
    // that hook is a byte-for-byte duplicate of FP_FRB01's own hook at the
    // exact same address/register/predicate. Removed the duplicate
    // registration; FP_FRB01 already covers that case. This function now
    // only hooks its own distinct case (pBuffPtr==NULL in I2C_ITError).
    if (reg_state[2] == 0) {
        report_detected_triggered("FP_FW22");
    }
}

// -------------FW23-------------
// Dangling pointer from pwm_start
int pwm_start = 0;
void pwm_ret() {
    //PWM_START_RETURN
    pwm_start = 0;
    report_reached("FW23");
    // timer_handles[1]
    frb_mem_write(0x20000610,0xDEADBEEF,4);

}
void pwm_started() {
    report_reached("FW23");
    pwm_start=1;
}

void check_FW23_use(){
    uint32_t ptr = frb_mem_read(0x20000610,4);
    if (ptr == 0xDEADBEEF || pwm_start == 1) {
        report_detected_triggered("FW23");
    }
}
// -------------FW23-------------

void BUG_E01() {
    report_reached("E01");
    // Unchecked error in decodeByteStream
    if (reg_state[0] != 0) {
        report_detected_triggered("E01");
    }
}

void BUG_MF01() {
    report_reached("MF01");
    // Incorrect handling of zero length sysex messages
    if (reg_state[1] < 1) {
        report_detected_triggered("MF01");
    }
}

void BUG_FP_FRB01() {
    report_reached("FP_FRB01");
    // unitilised DMA use in I2C_Slave_STOPF
    if (reg_state[2] == 0) {
        report_detected_triggered("FP_FRB01");
    }
}

void BUG_FP_FRB02() {
    report_reached("FP_FRB02");
    // unitilised DMA use in I2C_IT_ERROR
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB02");
    }
}

// RE-INSTATED 2026-07-17 (deleted as FP_FRB03 on 2026-07-15; kept its
// original ID rather than taking a new one -- this is the same raven,
// corrected, not a new finding). The 2026-07-15 removal claimed "pBuffPtr
// legitimately exceeds the constant during ordinary I2C operation, so it
// was true almost always" -- live TriAgent triage of a previously-
// ungrouped crash (0x8002309_0x8002ed0_read_error) disproved that: pBuffPtr
// sits at Wire+124 (0x2000038c) with a 32-byte window during ordinary
// HAL_I2C_Slave_Sequential_Receive_IT operation, well under this
// threshold. It only crosses 0x200003d0 after sustained I2C bus-error
// interrupts keep re-entering I2C_ITError's error-logging append path past
// the declared Size, walking pBuffPtr unboundedly past Wire's own storage
// -- proven to corrupt Firmata._firmataStream 228 bytes past the buffer's
// declared end, causing a NULL-vtable crash in FirmataClass::available()
// on the very next call. Status corrected false_positive -> confirmed. See
// bug_analysis/bugs/FRB03.md and bug_analysis/bug_history.md.
void BUG_FRB03() {
    report_reached("FRB03");
    // hi2c->pBuffPtr (r2) about to be stored through; I2C_ITError never
    // bounds it against hi2c->XferSize/XferCount. 0x200003d0 is one-past-
    // the-end of the Wire object itself (== &Firmata) -- a sound proxy in
    // this firmware since Wire's own declared receive buffers never
    // approach it (see bug_analysis/bugs/FRB03.md for the general-case
    // caveat).
    if (reg_state[2] > 0x200003d0) {
        report_detected_triggered("FRB03");
    }
}

void BUG_FP_FRB04() {
    report_reached("FP_FRB04");
    // Uninitialized DMA use in I2C_MasterReceive_BTF
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB04");
    }
}

// REMOVED 2026-07-15: FP_FRB10 checked TwoWire::write's txBufferLength
// against a fixed threshold (7) that never corresponded to any real
// capacity limit -- the function dynamically grows its tx buffer via
// realloc (capped at 32 bytes) and NULL-checks the result before ever
// storing, so there is no length at which the store becomes unsafe. Not a
// weak/imprecise proxy for a real bug (the way some other false_positive
// ravens in this file still are) -- there is no unsafe condition in this
// function for any raven to detect. Fired constantly on ordinary I2C
// traffic (thousands of times per campaign run) for no diagnostic value.
// See bug_analysis/triage-log.md.

void register_reflection_points() {
    frb_add_reflection_point(0x08002fc6, BUG_FW12);
    frb_add_reflection_point(0x0800878e, BUG_FP_FW21);
    frb_add_reflection_point(0x08008768, BUG_FP_FW21);
    frb_add_reflection_point(0x0800501c, BUG_FP_FW22);
    frb_add_reflection_point(0x0800501c, BUG_FRB03);
    frb_add_reflection_point(0x080071ac, pwm_ret);
    frb_add_reflection_point(0x08005e72, check_FW23_use);
    frb_add_reflection_point(0x0800348a, BUG_E01);
    frb_add_reflection_point(0x08003422, BUG_MF01);
    frb_add_reflection_point(0x0800515a, BUG_FP_FRB01);
    frb_add_reflection_point(0x080050da, BUG_FP_FRB01);
    frb_add_reflection_point(0x08004f8e, BUG_FP_FRB02);
    frb_add_reflection_point(0x08004e5e, BUG_FP_FRB04);
    frb_add_reflection_point(0x0800711c, pwm_started);
}
