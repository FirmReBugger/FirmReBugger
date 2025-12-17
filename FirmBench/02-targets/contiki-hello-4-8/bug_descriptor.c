#include <tcclib.h>
#include <stdint.h>
#include <stdbool.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern uint32_t frb_report_reached(char* bug_id);
extern uint32_t frb_report_detected_triggered(char* bug_id);

typedef void (*func_ptr_t)(void);

typedef struct {
    uint32_t address;
    func_ptr_t bug_func;
} context_struct;

static void report_detected_triggered(char* bug_id) {
    frb_report_detected_triggered(bug_id);
    // frb_report_detected_triggered(bug_id);
}

static void report_reached(char* bug_id) {
    frb_report_reached(bug_id);
    // frb_report_reached(bug_id);
}

static uint32_t PACKETBUF_ALIGNED = 0x200006b0;
static uint32_t PACKETBUF_ALIGNED_LEN = 32 * 4;

static uint32_t UIP_BUF = 0x200025ec;
static uint32_t UIP_BUFSIZE = 1280;

// Bug: new-Bug-l2cap_mtu_6lo_output_packetbuf_oob_write
// We hook memcpy calls with LRs known to originate from 6lo (checks relying on BLE_L2CAP_NODE_MTU) and l2cap (missing check)
// PORTING: memcpy call in function "output" (inlined compress_hdr_iphc) with variable size and related to the "hc06_ptr" variable
static uint32_t MEMCPY_CALL_LOC_COMPRESS_HDR_IPHC_PACKETBUF_OOB = 0x00207cac;
// PORTING: memcpy call in function "output" (!frag_needed case) with variable size which is followed by function "send_packet"
static uint32_t MEMCPY_CALL_LOC_OUTPUT_PACKETBUF_OOB = 0x00207e4e;
// PORTING: memcpy call in function "process_thread_ble_l2cap_tx_process" with variable size which is followed by packetbuf_set_datalen / ... / send
static uint32_t MEMCPY_CALL_LOC_BLE_L2CAP_TX_PROCESS = 0x002056ca;
// PORTING: memcpy call in function "fragment_copy_payload_and_send". These OOBs (always) originate from output->fragment_copy_payload_and_send->memcpy
static uint32_t MEMCPY_CALL_LOC_fragment_copy_payload_and_send = 0x00204c12;
// PORTING: memcpy call in function "packetbuf_copyfrom". These OOBs (always) originate from output->fragment_copy_payload_and_send->queuebuf_to_packetbuf->packetbuf_copyfrom->memcpy
static uint32_t MEMCPY_CALL_LOC_packetbuf_copyfrom = 0x002076ce;
// PORTING: memcpy call in function "compress_addr_64" (first call with constant size 2). These OOBs (always) originate from output->compress_addr_64->memcpy
static uint32_t MEMCPY_CALL_LOC_output_compress_addr_64_1 = 0x00207646;
// PORTING: memcpy call in function "compress_addr_64" (second call with constant size 8). These OOBs (always) originate from output->compress_addr_64->memcpy
static uint32_t MEMCPY_CALL_LOC_output_compress_addr_64_2 = 0x0020765a;
// There are different, fixed/small-sized memcpy calls which may OOB in more niche situations create a catch-all here
// PORTING: sicslowpan_driver.output (mem.u32(symbols["sicslowpan_driver"]+0xc))
static uint32_t SICSLOWPAN_DRIVER_OUTPUT_FN = 0x00207720;
static uint32_t SICSLOWPAN_DRIVER_OUTPUT_FN_END = 0x00207e74;

// memcpy packetbuf OOB cases
// PORTING: Hook return from memcpy call in input following packetbuf_dataptr (this matches the return for call hooked for unchecked_sdu_length)
static uint32_t MEMCPY_CALL_LOC_PACKETBUF_KNOWN_UNCHECKED_SDU = 0x00205c1a;
// PORTING: Hook return matching the first H05 hook memcpy call in input
static uint32_t MEMCPY_CALL_LOC_PACKETBUF_KNOWN_H05_1 = 0x00205bba;
// PORTING: Hook return matching the second H05 hook memcpy call in input
static uint32_t MEMCPY_CALL_LOC_PACKETBUF_KNOWN_H05_2 = 0x00205be4;
// PORTING: Return from memcpy in input following assignment of packetbuf_payload_len and other OOB against IP packet length
// Fix: https://github.com/contiki-ng/contiki-ng/commit/c76aa9bc
static uint32_t MEMCPY_CALL_LOC_SICSLOWPAN_FIRSTFRAG_OR_UNFRAG_OOB = 0x0020888c;
// PORTING: memcpy call in function "input" with variable size and related to the "hc06_ptr" variable
static uint32_t MEMCPY_CALL_LOC_UNCOMPRESS_HDR_IPHC = 0x002085f6;

// Bugs: fixed-Bug-uncompress_hdr_iphc_oob_write
// PORTING: Symbol: frag_info
static uint32_t FRAG_INFO = 0x20000a10;
// sicslowpan_frag_info frag_info[2]
static uint32_t FRAG_INFO_SIZE = 2 * 0xb8;

void H03() {
    uint32_t packetbuf_dataptr = reg_state[0];
    uint32_t channel = reg_state[6];
    report_reached("H03");
    uint32_t sdu_length = frb_mem_read(channel + 0xa14,2);
    //Fix: https://github.com/contiki-ng/contiki-ng/commit/506f9def7cdff853fa24cf6d88e1f4e5619dc46c
    if ((packetbuf_dataptr + sdu_length) > (PACKETBUF_ALIGNED + PACKETBUF_ALIGNED_LEN)) {
        report_detected_triggered("H03");
        //frb_force_crash();
    }
}

static int recusion_depth = 0;

void H04_enter () {
    report_reached("H04");
    recusion_depth ++;
    if (recusion_depth > 10) {
        report_detected_triggered("H04");
        // frb_force_crash();
    }
}

void H04_return () {
    recusion_depth --;
}

void H05_1 () {
    uint32_t sp = reg_state[13];
    uint32_t len = frb_mem_read(sp + 4, 2);
    uint32_t res = len - 2;
    report_reached("H05");
    if (res > 0x500 || res < 0) {
        report_detected_triggered("H05");
        // frb_force_crash();
    }
}

void H05_2 () {
    uint32_t sp = reg_state[13];
    uint32_t len = frb_mem_read(sp + 4, 2);

    uint32_t current_index = frb_mem_read(reg_state[9] + 0xa16,2);
    uint32_t res = current_index + len;
    report_reached("H05");
    if (res > 0x500 || res < 0) {
        report_detected_triggered("H05");
        // frb_force_crash();
    }
}

void on_packetbuf_oob_writes (){
    report_reached("H06");
    report_reached("H07");
    uint32_t dst = reg_state[0];
    uint32_t lr = reg_state[14];

    // Check for any copies targeting packetbuf
    if ((dst >= PACKETBUF_ALIGNED) && (dst < PACKETBUF_ALIGNED + PACKETBUF_ALIGNED_LEN)){
        //Remaining buffer size: buffer len minus buffer cursor offset
        uint32_t buf_size = PACKETBUF_ALIGNED_LEN - (dst - PACKETBUF_ALIGNED);
        uint32_t n = reg_state[2];

    if (n > buf_size) {
            bool is_H05 = (lr == (MEMCPY_CALL_LOC_PACKETBUF_KNOWN_H05_1 | 1)) ||
                                    (lr == (MEMCPY_CALL_LOC_PACKETBUF_KNOWN_H05_2 | 1));

            bool is_ble_l2cap_MTU_output_OOB = false;

            // output OOB: Specific output call sites
            is_ble_l2cap_MTU_output_OOB = is_ble_l2cap_MTU_output_OOB || 
                                        (lr == (MEMCPY_CALL_LOC_COMPRESS_HDR_IPHC_PACKETBUF_OOB | 1) ||
                                        lr == (MEMCPY_CALL_LOC_OUTPUT_PACKETBUF_OOB | 1) ||
                                        lr == (MEMCPY_CALL_LOC_BLE_L2CAP_TX_PROCESS | 1));

            // output OOB: Specific OOBs in fragment_copy_payload_and_send
            is_ble_l2cap_MTU_output_OOB = is_ble_l2cap_MTU_output_OOB || 
                                        (lr == (MEMCPY_CALL_LOC_fragment_copy_payload_and_send | 1) ||
                                        lr == (MEMCPY_CALL_LOC_packetbuf_copyfrom | 1));

            // output OOB: Specific OOBs in compress_addr_64
            is_ble_l2cap_MTU_output_OOB = is_ble_l2cap_MTU_output_OOB || 
                                        (lr == (MEMCPY_CALL_LOC_output_compress_addr_64_1 | 1) ||
                                        lr == (MEMCPY_CALL_LOC_output_compress_addr_64_2 | 1));

            // output OOB: Catch-all for Niche OOBs with small and constant-size memcpy calls
            is_ble_l2cap_MTU_output_OOB = is_ble_l2cap_MTU_output_OOB || 
                                        ((lr >= SICSLOWPAN_DRIVER_OUTPUT_FN && lr < SICSLOWPAN_DRIVER_OUTPUT_FN_END) &&
                                        (n > 0 && n < 0x20));

            // Conditions to ignore known packetbuf OOB write sources
            if (is_H05 || 
                lr == (MEMCPY_CALL_LOC_PACKETBUF_KNOWN_UNCHECKED_SDU | 1) ||
                lr == (MEMCPY_CALL_LOC_SICSLOWPAN_FIRSTFRAG_OR_UNFRAG_OOB | 1)) {
                return;
            } else if (lr == (MEMCPY_CALL_LOC_UNCOMPRESS_HDR_IPHC | 1)) {
                // Log a specific bug related to uncompress_hdr_iphc_oob_write
                report_detected_triggered("H07");
                // frb_force_crash();
            } else if (is_ble_l2cap_MTU_output_OOB) {
                report_detected_triggered("H06");
                // frb_force_crash();
            } 
        }
    }
}

void on_fraginfo_oob_writes () {
    report_reached("H07");
    report_reached("H08");
    uint32_t dst = reg_state[0];
    //Check for any copies targeting fragment buffers
    if ((dst >= FRAG_INFO) && (dst < FRAG_INFO + FRAG_INFO_SIZE)) {
        //Remaining buffer size: buffer len minus buffer cursor offset
        uint32_t buf_size = FRAG_INFO_SIZE - (dst - FRAG_INFO);
        uint32_t n = reg_state[2];

        if (n > buf_size) {
            uint32_t lr = reg_state[14];
            if (lr == (MEMCPY_CALL_LOC_UNCOMPRESS_HDR_IPHC | 1)) {
                //Fix commits:
                //uncompress_hdr_iphc retval: https://github.com/contiki-ng/contiki-ng/commit/971354a
                //uncompress_hdr_iphc bufsize arg: https://github.com/contiki-ng/contiki-ng/commit/b88e5c3
                //Main checks: https://github.com/contiki-ng/contiki-ng/commit/668f244
                //Off-by-one fix: https://github.com/contiki-ng/contiki-ng/commit/79cd1d6
                report_detected_triggered("H07");
                // frb_force_crash();
            }else if (lr == (MEMCPY_CALL_LOC_SICSLOWPAN_FIRSTFRAG_OR_UNFRAG_OOB | 1)) {
                //buffer_size tracking: https://github.com/contiki-ng/contiki-ng/commit/b88e5c3
                //buffer_size oob check: https://github.com/contiki-ng/contiki-ng/commit/c76aa9bc
                report_detected_triggered("H08");
                // frb_force_crash();
            }
        }
    }
}

void on_rpl_ext_header_srh_update() {
    report_reached("H09");
    report_reached("H10");
    uint8_t RPL_RH_LEN = 4;
    uint8_t RPL_SRH_LEN = 4;

    uint32_t rh_header = reg_state[0];
    // Read rh_header->len
    uint8_t len = frb_mem_read(rh_header + 1,1);

    uint8_t ext_len = len * 8 + 8;
    uint32_t srh_header = rh_header + RPL_RH_LEN;

    // Read rh_header->seg_left
    uint8_t segments_left = frb_mem_read(rh_header + 3, 1);

    // Read srh_header->cmpr
    uint8_t cmpr = frb_mem_read(srh_header + 0,1);

    uint8_t cmpri = cmpr >> 4;
    uint8_t cmpre = cmpr & 0x0f;

    // Read srh_header->pad
    uint8_t padding = frb_mem_read(srh_header + 1,1) >> 4;

    uint8_t path_len = ((ext_len - padding - RPL_RH_LEN - RPL_SRH_LEN - (16 - cmpre)) / (16 - cmpri)) + 1;

    // Check for too many segments left
    if (segments_left > path_len) {
        report_detected_triggered("H09");
        // frb_force_crash();
    }

    uint8_t i = path_len - segments_left;
    cmpr = (segments_left == 1) ? cmpre : cmpri;
    uint32_t rh_offset = rh_header - (uint32_t)UIP_BUF;
    uint32_t addr_offset = RPL_RH_LEN + RPL_SRH_LEN + (i * (16 - cmpri));

    // Check for invalid SRH address pointer
    if (rh_offset + addr_offset + 16 - cmpr > UIP_BUFSIZE) {
        report_detected_triggered("H10");
        // frb_force_crash();
    }
}

void H11() {
    // CVE-2022-41873
    report_reached("H11");
    uint32_t r8 = reg_state[8];
    if ((r8>>8) & 0xff != 0) {
        report_detected_triggered("H11");
    }
}

void H12() {
    // CVE-2022-4197
    report_reached("H12");
    uint32_t r5 = reg_state[5];
    if (r5 == 0) {
        report_detected_triggered("H12");
    }
}

void l2cap_channels() {
    report_reached("FRB20");
    uint8_t l2p_cap_channel_count = frb_mem_read(0x20001eaa, 1);
    if (reg_state[6] >= l2p_cap_channel_count) {
        report_detected_triggered("FRB20");
    }
}

context_struct context_array[] = {
    {0x00205c0a, H03},
    {0x00206b1e, H04_return},
    {0x00206b1a, H04_enter},
    {0x00205b94, H05_1},
    {0x00205bc4, H05_2},
    {0x0020ab70, on_packetbuf_oob_writes},
    {0x0020ab70, on_fraginfo_oob_writes},
    {0x00209218, on_rpl_ext_header_srh_update},
    {0x00205b46, H11},
    {0x0020b3bc, H12},
    {0x0000205b84, l2cap_channels},
    {0x00205c3c, l2cap_channels}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}

// static void print_reg_state(uint32_t *reg_state){
//     printf("Register State:\n");
//     printf("r0:  0x%08X\n", reg_state[0]);
//     printf("r1:  0x%08X\n", reg_state[1]);
//     printf("r2:  0x%08X\n", reg_state[2]);
//     printf("r3:  0x%08X\n", reg_state[3]);
//     printf("r4:  0x%08X\n", reg_state[4]);
//     printf("r5:  0x%08X\n", reg_state[5]);
//     printf("r6:  0x%08X\n", reg_state[6]);
//     printf("r7:  0x%08X\n", reg_state[7]);
//     printf("r8:  0x%08X\n", reg_state[8]);
//     printf("r9:  0x%08X\n", reg_state[9]);
//     printf("r10: 0x%08X\n", reg_state[10]);
//     printf("r11: 0x%08X\n", reg_state[11]);
//     printf("r12: 0x%08X\n", reg_state[12]);
//     printf("sp:  0x%08X\n", reg_state[13]);
//     printf("lr:  0x%08X\n", reg_state[14]);
//     printf("pc:  0x%08X\n", reg_state[15]);
// }