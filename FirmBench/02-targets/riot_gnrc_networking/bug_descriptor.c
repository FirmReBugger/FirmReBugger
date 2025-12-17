#include <tcclib.h>
#include <stdint.h>
#include <stdbool.h>

extern uint32_t reg_state[16];
extern uint32_t frb_mem_read(uint32_t read_addr, size_t size);
extern void frb_report_detected_triggered(char* bug_id);
extern void frb_report_reached(char* bug_id);

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

typedef void (*func_ptr_t)(void);

typedef struct {
    uint8_t missing_src;
} NetifHdr;

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

void H19() {
    report_reached("H19");
    uint32_t rh = reg_state[1];
    uint8_t len = frb_mem_read(rh + 1, 1);
    uint8_t compre = frb_mem_read(rh + 4, 1) & 0x0F;
    uint8_t padding = frb_mem_read(rh + 5, 1) >> 4;

    if (len * 8 < padding + (16 - compre)) {
        report_detected_triggered("H19");
    }
}

uint8_t missing_src = 0;

void gnrc_sixlowpan_frag_vrb_get(r) {
    uint32_t src_len = reg_state[1];  
    if (src_len == 0) {
        missing_src = 1;
    }
}

void gnrc_netif_hdr_build() {
    report_reached("H20");
    uint32_t src_len = reg_state[1];  
    if (src_len == 0 && missing_src == 1) {
        report_detected_triggered("H20");
    }
}

void H21(){
    report_reached("H21");
    uint32_t ipv6 = reg_state[6]; 
    uint32_t ipv6_size = frb_mem_read(ipv6 + 8, 4); 
    uint32_t uncomp_header_len = reg_state[5];  
    uint32_t copy_size = reg_state[2];  

    if (uncomp_header_len + copy_size > ipv6_size) {
        report_detected_triggered("H21");
    }
}

void H22() {
    report_reached("H22");
    uint32_t sixlo_size = reg_state[2];  
    uint32_t payload_offset = reg_state[4];  

    if (payload_offset > sixlo_size) {
        // subtraction causes integer underflow
        report_detected_triggered("H22");
    }
}

void H23() {
    report_reached("H23");
    uint32_t frag_size = reg_state[4];

    if (frag_size > 0x80000000) {
        // Integer underflow detected
        report_detected_triggered("H23");
    }
}

void H24() {
    report_reached("H24");
    uint32_t pkt = reg_state[7];  
    uint32_t next = frb_mem_read(pkt, 4); 
    uint32_t next_next = frb_mem_read(next, 4);  

    if (next_next == 0) {
        // Null pointer detected
        report_detected_triggered("H24");
    }
}

void H25() {
    report_reached("H25");
    uint32_t snippet = reg_state[3];  
    uint32_t size = frb_mem_read(snippet + 8, 4); 

    if (size > 8) {
        // actual snippet size is larger than the udp header
        report_detected_triggered("H25");
    }
}

uint8_t data_nullptr = 0;

void gnrc_pktbuf_mark() {
    uint32_t pkt = reg_state[0];  
    uint32_t pkt_size = frb_mem_read(pkt + 8, 4);  
    uint32_t mark_size = reg_state[1];  

    if (pkt_size == mark_size) {
        data_nullptr = 1;
    }
}

void gnrc_sixlowpan_iphc_recv() {
    report_reached("H26");
    uint32_t sixlo = reg_state[0];  
    uint32_t data = frb_mem_read(sixlo + 4, 4);  

    // Check NULL pointer deref on sixlo->data
    if (data == 0 && data_nullptr == 1) {
        report_detected_triggered("H26");
    }
}

void H27() {
    report_reached("H27");
    uint32_t timer = 0x2000c9dc;  // timer
    uint32_t callback = frb_mem_read(timer + 8, 4);  

    if (callback == 0) {
        // Timer is not initialized but gets scheduled
        report_detected_triggered("H27");
    }
}

bool check_freed(uint32_t addr) {
    const uint32_t _first_unused = 0x20007268;
    uint32_t block_ptr = frb_mem_read(_first_unused, 4);

    while (block_ptr != 0) {
        uint32_t next_ptr = frb_mem_read(block_ptr, 4);
        uint32_t block_size = frb_mem_read(block_ptr + 4, 4);
        // printf("Checking block at 0x%08X with size %u\n", block_ptr, block_size);

        if (addr >= block_ptr && addr < block_ptr + block_size) {
            return true;
        }

        block_ptr = next_ptr;
    }
    return false;
}

void shell_command() {
    report_reached("FP_FRB23");
    if (reg_state[0] == 0) {
        report_detected_triggered("FP_FRB23");

    }
}

void core_panic_exit() {
    report_reached("FP_FRB31");
    report_detected_triggered("FP_FRB31");
}

// void on_gnrc_pktbuf_hold() {
//     report_reached("gnrnc_pktbuf_hold");
//     if (check_freed(reg_state[0])) {
//         report_detected_triggered("gnrc_pktbuf_hold");
//     }
// }

// bool msg_recieve_flag = 0;
// void msg_receive_start() {
//     msg_recieve_flag = 1;
//     // printf("on_msg_reieve: ptr = 0x%08X\n", ptr);
// }

// void msg_receive_end() {
//     msg_recieve_flag = 0;
// }

// void on_release() {
//     report_reached("FP_FRB27");
//     if (msg_recieve_flag) {
//         report_detected_triggered("FP_FRB27");
//     }
// }

// void send_check() {
//     report_reached("send_check");
//     if(check_freed(reg_state[0]) || check_freed(reg_state[1])) {
//         report_detected_triggered("send_check");
//     }
// } 

// void on_msg_send() {
//     report_reached("on_msg_send");
//     uint32_t ptr = frb_mem_read(reg_state[0]+4, 4);
//     // printf("on_msg_send: ptr = 0x%08X\n", ptr);
//     if (check_freed(ptr)) {
//         report_detected_triggered("on_msg_send");
//     }
// }

// void event_loop_check() {
//     report_reached("event_loop_check");
//     if (check_freed(0x2000748c ) || check_freed(reg_state[0])) {
//         report_detected_triggered("event_loop_check");
//     }
//     printf("ASDKASDBASD\n");
// }

void RFCORE_ASSERT_failure_exit() {
    report_reached("FP_FRB32");
    report_detected_triggered("FP_FRB32");
}

// void on_gnrc_sixlowpan_dispatch_send() {
//     report_reached("gnrc_sixlowpan_dispatch_send");
//     if (check_freed(reg_state[0])) {
//         report_detected_triggered("gnrc_sixlowpan_dispatch_send");
//     }
// }

void check_wildcard_udp() {
    report_reached("FP_FRB35");
    uint32_t pkt_type = reg_state[0] + 0x10;
    if (pkt_type != 0xfd || pkt_type != 0xff || pkt_type != 0x0 || pkt_type != 0x1 || pkt_type != 0x2 || pkt_type != 0x3 || pkt_type != 0x4 || pkt_type != 0x5 || pkt_type != 0x6 || pkt_type != 0x7) {
        report_detected_triggered("FP_FRB35");
    }
}

void on_gnrc_ipv6_ext_process_all() {
    report_reached("FP_FRB36");
    if (reg_state[3] == 0) {
        report_detected_triggered("FP_FRB36");
    }
}

void on_gnrc_sixlowpan_iphc_revec() {
    report_reached("FP_FRB37");
    // Check NULL pointer deref on sixlo->data
    if (reg_state[11] == 0) {
        report_detected_triggered("FP_FRB37");
    }
}


context_struct context_array[] = {
    {0x0020c994, H19},
    {0x0020a3c0, gnrc_netif_hdr_build},
    {0x0020ea14, gnrc_sixlowpan_frag_vrb_get},
    {0x0020fbea, H21},
    {0x0020fbe2, H22},
    {0x0020d682, H23},
    {0x0020f156, H24},
    {0x0020f10e, H25},
    {0x0020f7b8, gnrc_sixlowpan_iphc_recv},
    {0x0020ad4c, gnrc_pktbuf_mark},
    {0x0020dd20, H27},
    {0x00213e28, shell_command},
    {0x00201738, core_panic_exit},
    // {0x0020abd4, on_gnrc_pktbuf_hold},
    // {0x00200dc8, msg_receive_start},
    // {0x00200dfc, msg_receive_end},
    // {0x0020aa38, on_release},
    // {0x20acc8, set_pkt_snip},
    // {0x00202af4, send_check},
    // {0x0020396c, send_check},
    // {0x00203dc0, send_check},
    // {0x00208ed4, send_check},
    // {0x0020a2a8, send_check},
    // {0x0020a4f0, send_check},
    // {0x00212d82, send_check},
    // {0x0021181c, event_loop_check},
    {0x00200468, RFCORE_ASSERT_failure_exit},
    // {0x0020cb86, on_gnrc_sixlowpan_dispatch_send},
    //     {0x0020e9ba, test},
    {0x0021181c, check_wildcard_udp},
    {0x0020469a, on_gnrc_ipv6_ext_process_all},
    {0x0020fbde, on_gnrc_sixlowpan_iphc_revec},
    // {0x00201020, on_msg_send},
    // {0x0020cb54, on_gnrc_sixlowpan_dispatch_send_0}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
