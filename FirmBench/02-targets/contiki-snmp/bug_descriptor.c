#include <tcclib.h>
#include <stdint.h>
#include <stdbool.h>

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

uint32_t OID_END = 0x20000c10;
uint32_t PACKET_LEN_PTR = 0x20000bcc;
uint32_t PACKET_LEN = 512;

typedef struct {
    uint32_t buf;
    uint32_t buf_len;
} SnmpArgs;

SnmpArgs args_decode_generic = { .buf = 0, .buf_len = 0 };
SnmpArgs args_encode_generic = { .buf = 0, .buf_len = 0 };


void init_buf_len_decode() {
    args_decode_generic.buf_len = reg_state[1];
}

void init_buf_len_encode() {
    args_encode_generic.buf_len = reg_state[1];
}

void on_snmp_message_decode_check_bounds_generic() {
    report_reached("H14");
    // only validate in snmp_message_decode

    uint32_t sp = reg_state[13];
    uint32_t buf_len = frb_mem_read(sp + 4,4);
    //printf("buf_len: 0x%08X > args_decode_generic: 0x%08X\n", buf_len, args_decode_generic.buf_len);

    // verify buf_len never increases
    if (buf_len > args_decode_generic.buf_len) {
        // NOTE: this is a more generic check for OOB's in H14
        report_detected_triggered("H14");
    }

    // update last buf_len
    args_decode_generic.buf_len = buf_len;
}

void on_snmp_message_encode_check_bounds_generic() {
    report_reached("H14");
    // only validate in snmp_message_decode

    uint32_t sp = reg_state[13];
    uint32_t out_len = frb_mem_read(sp + 4,4);
    //printf("out_len: 0x%08X > args_encode_generic: 0x%08X\n", out_len, args_encode_generic.buf_len);

    // verify buf_len never increases
    if (out_len > args_encode_generic.buf_len) {
        // NOTE: this is a more generic check for OOB's in H14
        report_detected_triggered("H14");
    }

    // update last out_len
    args_encode_generic.buf_len = out_len;
}

void on_snmp_message_encode_oid_check_bounds_generic() {
    report_reached("H14");
    // only validate in snmp_message_decode

    uint32_t sp = reg_state[13];
    uint32_t out_len = reg_state[1];
    //printf("out_len: 0x%08X > args_encode_generic: 0x%08X\n", out_len, args_encode_generic.buf_len);

    // verify buf_len never increases
    if (out_len > frb_mem_read(sp + 4, 4)) {
        // NOTE: this is a more generic check for OOB's in H14
        report_detected_triggered("H14");
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

void on_snmp_oid_copy_write() {
    report_reached("H17");
    // Before writing in snmp_oid_copy, check that the index is in bounds of 16 u32's

    // Porting: r2 == i
    uint32_t OID_ARR_SIZE = 16;
    uint32_t write_ind = reg_state[2];

    if (write_ind >= OID_ARR_SIZE) {
        report_detected_triggered("H17");
    }
}


context_struct context_array[] = {
    {0x00208778, on_snmp_oid_decode_oid_oob},
    {0x002058b0, init_buf_len_decode},
    {0x00208540, init_buf_len_encode},
    {0x002058c2, on_snmp_message_decode_check_bounds_generic},
    {0x00205908, on_snmp_message_decode_check_bounds_generic},
    {0x0020592a, on_snmp_message_decode_check_bounds_generic},
    {0x0020594e, on_snmp_message_decode_check_bounds_generic},
    {0x00205990, on_snmp_message_decode_check_bounds_generic},
    {0x002059c8, on_snmp_message_decode_check_bounds_generic},
    {0x002059d6, on_snmp_message_decode_check_bounds_generic},
    {0x002059fa, on_snmp_message_decode_check_bounds_generic},
    {0x00205a1e, on_snmp_message_decode_check_bounds_generic},
    {0x00205a44, on_snmp_message_decode_check_bounds_generic},
    {0x00205a60, on_snmp_message_decode_check_bounds_generic},
    {0x00205aa2, on_snmp_message_decode_check_bounds_generic},
    {0x00205aba, on_snmp_message_decode_check_bounds_generic},
    {0x00205b28, on_snmp_message_decode_check_bounds_generic},
    {0x00205a82, on_snmp_message_decode_check_bounds_generic},
    {0x00205b30, on_snmp_message_decode_check_bounds_generic},
    {0x00205b1c, on_snmp_message_decode_check_bounds_generic},
    {0x002085ee, on_snmp_message_encode_check_bounds_generic}, 
    {0x002085f6, on_snmp_message_encode_check_bounds_generic},
    {0x00208606, on_snmp_message_encode_check_bounds_generic},
    {0x0020860e, on_snmp_message_encode_check_bounds_generic},
    {0x0020861c, on_snmp_message_encode_check_bounds_generic},
    {0x00208624, on_snmp_message_encode_check_bounds_generic},
    {0x0020862e, on_snmp_message_encode_check_bounds_generic},
    {0x00208636, on_snmp_message_encode_check_bounds_generic},
    {0x00208644, on_snmp_message_encode_check_bounds_generic},
    {0x00208650, on_snmp_message_encode_check_bounds_generic},
    {0x002086ac, on_snmp_message_encode_oid_check_bounds_generic}, //oid encode
    {0x002085b2, on_snmp_message_encode_check_bounds_generic}, //oid encode
    {0x002085a8, on_snmp_message_encode_check_bounds_generic},
    {0x00208582, on_snmp_message_encode_check_bounds_generic}, //integer encode
    {0x0020859c, on_snmp_message_encode_check_bounds_generic},
    {0x002085ba, on_snmp_message_encode_check_bounds_generic},
    {0x002085c2, on_snmp_message_encode_check_bounds_generic},
    {0x002085d0, on_snmp_message_encode_check_bounds_generic},
    {0x002085da, on_snmp_message_encode_check_bounds_generic},
    {0x00208a7c, on_snmp_engine_get_bulk},
    {0x002087e0, on_snmp_oid_copy_write}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}