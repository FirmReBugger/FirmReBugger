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

bool mtu_setup = false;
uint32_t semaphores[100];
int sem_count = 0;

void bt_init() {
    mtu_setup = true;
}

void on_semapore_init(){
    // FP GENERIC-invalid-sem-init
    report_reached("H35");
    uint32_t semaphore = reg_state[0];
    semaphores[sem_count] = semaphore;
    sem_count++;
    // Invalid semaphore initialization check
    uint32_t initial_count = reg_state[1];
    uint32_t limit = reg_state[2];
    if (limit == 0 || initial_count > limit) {
        report_detected_triggered("H35");
    }
}

void BUG_H32() {
    // CVE-2021-3329
    report_reached("H32");
    uint32_t sem = 0x20002f7c;
    bool init = false;

    for (int i = 0; i < sem_count; i++) {
        if (semaphores[i] == sem) {
            init = true;
            break;
        }
    }

    if (mtu_setup && !init) {
        report_detected_triggered("H32");
    }
}

void use_sem_before_init() {
    // FP GENERIC-sem-not-init
    report_reached("H33");
    uint32_t sem = reg_state[0];

    bool init = false;
    for (int i = 0; i < sem_count; i++) {
        if (semaphores[i] == sem) {
            init = true;
            break;
        }
    }

    if (!init) {
        report_detected_triggered("H33");
    }
}

void on_timeout_callback() {
    // FP GENERIC-invalid_timeout_callback
    report_reached("H34");
    uint32_t t = reg_state[0];
    uint32_t callback = frb_mem_read(t + 0xc, 4);

    if (callback == 0) {
        report_detected_triggered("H34");
    }
}

void on_tx_free() {
    report_reached("H36");
    uint32_t tx = reg_state[0];

    if (tx & 0xff == 0x02) {
        report_detected_triggered("H36");
    }
}

void on_net_buf_simple_push() {
    report_reached("H37");

    uint32_t buf = reg_state[0];
    uint32_t len = reg_state[1];

    // Check space
    uint32_t buf_data = frb_mem_read(buf, 4);
    uint32_t buf_buf = frb_mem_read(buf + 8, 4);
    uint32_t buf_room = buf_data - buf_buf;

    if (buf_room < len) {
        report_detected_triggered("H37");
    }
}

bool fifo_contains(uint32_t fifo_addr, uint32_t buf) {
    uint32_t next = fifo_addr;
    uint32_t nodes[100];
    int node_count = 0;

    while (next != 0) {
        for (int i = 0; i < 100; i++) {
            if (nodes[i] == next) {
                return false;
            }
        }
        nodes[node_count] = next;
        node_count++;

        if (next == buf) {
            return true;
        }
        next = frb_mem_read(next, 4); // Read next pointer
    }
    return false;
}

void on_z_add_timeout() {
    // FP GENERIC-add_timeout-double-add
    // FP GENERIC-add_timeout-sys_dnode_is_linked
    report_reached("H38");
    report_reached("H39");
    uint32_t to = reg_state[0];
    uint32_t timeout_list = 0x20003148;

    if (fifo_contains(timeout_list, to)) {
        report_detected_triggered("H38");
    } 

    uint32_t next = frb_mem_read(to, 4);
    if (next != 0) {
        report_detected_triggered("H39");
    }
}

void on_k_delayed_work_init() {
    // FP GENERIC-delayed_work_init-double-add
    // FP GENERIC-add_timeout-sys_dnode_is_linked
    report_reached("H40");
    report_reached("H41");
    uint32_t work = reg_state[0];
    uint32_t to = work + 0xc;

    uint32_t timeout_list = 0x20003148;
    if (fifo_contains(timeout_list, to)) {
        report_detected_triggered("H40");
    }

    uint32_t next = frb_mem_read(to, 4);
    if (next != 0) {
        report_detected_triggered("H41");
    }
}

bool le_init_invalid = false;

void on_le_init_check_1() {
    uint32_t rsp_ptr_ptr = reg_state[13] + 4;
    uint32_t buf = frb_mem_read(rsp_ptr_ptr, 4);
    uint32_t data = frb_mem_read(buf + 8, 4);

    uint32_t le_max_len = frb_mem_read(data+1, 2);
    uint32_t le_max_num = frb_mem_read(data+3, 1);

    if (le_max_len != 0 && le_max_num == 0) {
        le_init_invalid = true;
    }
}

void on_le_init_check_2() {
    uint32_t rsp_ptr_ptr = reg_state[13] + 4;
    uint32_t buf = frb_mem_read(rsp_ptr_ptr, 4);
    uint32_t data = frb_mem_read(buf + 8, 4);

    uint32_t acl_max_num = frb_mem_read(data+4, 2);
  
    if (acl_max_num == 0) {
        le_init_invalid = true;
    }
}

void on_le_init_sem_take() {
    report_reached("H42");
    uint32_t sem = reg_state[0];
    if (sem == 0x20002F7C && le_init_invalid) {
        report_detected_triggered("H42");
    }
}

int isr_state_depth = 0;

void on_isr_state_enter() {
    isr_state_depth++;
}

void on_isr_state_exit() {
    isr_state_depth--;
}

void on_net_buf_alloc_len_ret_check_nullptr_in_isr() {
    // new-Bug-hci_prio_event_alloc_err_handling
    report_reached("H43");
    if (isr_state_depth > 0) {
        uint32_t buf = reg_state[4];
        uint32_t to = reg_state[6];

        if (to == 0xffffffff && buf == 0) {
            report_detected_triggered("H43");
        }
    }
}

typedef struct {
    bool bug;
    bool is_buf_handed_out_when_in_tx_fifo;
} SentCmdState;

static SentCmdState sent_cmd_state = { .bug = false, .is_buf_handed_out_when_in_tx_fifo = false };

void on_bt_buf_get_cmd_complete_sent_cmd_reuse() {
    uint32_t tx_fifo = 0x20003038;
    uint32_t sent_cmd_netbuf = reg_state[4];

    if (fifo_contains(tx_fifo, sent_cmd_netbuf)) {
        sent_cmd_state.is_buf_handed_out_when_in_tx_fifo = true;
    }
}

void on_net_buf_put_check_rx_tx_fifo_state() {
    //new-Bug-sent_cmd_shared_ref_race
    report_reached("H44");
    if (sent_cmd_state.is_buf_handed_out_when_in_tx_fifo) {
        uint32_t rx_fifo = 0x20003014;
        uint32_t tx_fifo = 0x20003038;

        uint32_t target_queue = reg_state[0];

        if (target_queue == rx_fifo) {
            uint32_t buf_to_add = reg_state[1];
            if (fifo_contains(tx_fifo, buf_to_add)) {
                report_detected_triggered("H44");
                sent_cmd_state.bug = true;
            }
        }
    }
}

typedef struct {
    bool valid;
    uint32_t head;
    uint32_t tail;
} SemaState;

static SemaState send_sync_sema_states[2] = {
    { .valid = false, .head = 0, .tail = 0 },
    { .valid = false, .head = 0, .tail = 0 }
};

void on_bt_hci_cmd_send_sync_set_valid() {
    uint32_t net_buf_id = reg_state[0];
    uint32_t sem = reg_state[13];

    if (net_buf_id == 0 || net_buf_id == 1) {
        send_sync_sema_states[net_buf_id].valid = true;
        send_sync_sema_states[net_buf_id].head = frb_mem_read(sem, 4);
        send_sync_sema_states[net_buf_id].tail = frb_mem_read(sem + 4, 4);
    }
}

void on_bt_hci_cmd_send_sync_set_invalid() {
    uint32_t net_buf_id = reg_state[0];
    if (net_buf_id == 0 || net_buf_id == 1) {
        send_sync_sema_states[net_buf_id].valid = false;
    }
}

void on_bt_hci_cmd_done_check_sema_validity() {
    report_reached("H45");
    uint32_t net_buf_id = reg_state[0];

    if (net_buf_id == 0 || net_buf_id == 1) {
        if (!send_sync_sema_states[net_buf_id].valid) {
            uint32_t sema_ptr_addr = 0x2000029c + net_buf_id * 0xc;
            uint32_t sema_addr = frb_mem_read(sema_ptr_addr, 4);
            uint32_t head = frb_mem_read(sema_addr, 4);
            uint32_t tail = frb_mem_read(sema_addr + 4, 4);
            if (send_sync_sema_states[net_buf_id].head != head ||
                send_sync_sema_states[net_buf_id].tail != tail) {
                report_detected_triggered("H45");
            }
        }
    }
}

typedef struct {
    uint32_t state;
    uint32_t state_target;
} CmdData;

static CmdData cmd_data[2] = {
    { .state = 0, .state_target = 0 },
    { .state = 0, .state_target = 0 }
};

void on_set_le_adv_enable_legacy_send_sync() {
    uint32_t idx = reg_state[0];
    uint32_t state = reg_state[13] + 4;
    uint32_t target = frb_mem_read(state, 4);

    if (idx >= 2) {
        return;
    }

    cmd_data[idx].state = state;
    cmd_data[idx].state_target = target;

}

void on_hci_cmd_done_state_update() {
    report_reached("H46");
    uint32_t idx = reg_state[0];
    if (idx >= 2) {
        return;
    }

    uint32_t cmd_data_ptr = 0x20000298 + (0xc* idx);
    uint32_t state = frb_mem_read(cmd_data_ptr, 4);

    if (state != 0) {
        uint32_t target = frb_mem_read(state, 4);
        if (target != cmd_data[idx].state_target) {
            report_detected_triggered("H46");
        }
    }

}

typedef struct {
    bool bug;
    bool pendsv;
} ArchSwap;

static ArchSwap arch_swap = { .bug = false, .pendsv = false };

void on_arch_swap_enter() {
    arch_swap.pendsv = false;
}

void on_z_arm_pendsv() {
    arch_swap.pendsv = true;
}

void on_arch_swap_after_pendsv() {
    if (!arch_swap.pendsv) {
        arch_swap.bug = true;
    }
}

void on_k_queue_get_poll() {
    report_reached("H47");
    uint32_t other_bug = arch_swap.bug || sent_cmd_state.bug;
    uint32_t node = reg_state[0];

    if (node ==0 && !other_bug) {
        report_detected_triggered("H47");
    }
}

void on_bt_att_sent() {
    report_reached("H48");
    uint32_t att = reg_state[6];
    if (att == 0) {
        report_detected_triggered("H48");
    } 
}

void on_bt_att_recv() {
    report_reached("H48");
    uint32_t att_chan = reg_state[6];
    uint32_t att = frb_mem_read(att_chan, 4);

    if (att == 0) {
        report_detected_triggered("H48");
    } 
}

void on_bt_att_status() {
    report_reached("H48");
    uint32_t att_chan = reg_state[0] - 4;
    uint32_t att = frb_mem_read(att_chan, 4);

    if (att == 0) {
        report_detected_triggered("H48");
    }
}

void on_conn_auto_initiate_call_work_submit() {
    report_reached("H49");
    uint32_t update_work = reg_state[4] + 0x50;
    uint32_t to = update_work + 0xc;

    uint32_t timeout_list = 0x20003148;
    if (fifo_contains(timeout_list, to)) {
        report_detected_triggered("H49");
    }
}

void on_bt_conn_add_le_work_init() {
    report_reached("H49");
    uint32_t update_work = reg_state[4] + 0x50;
    uint32_t to = update_work + 0xc;

    uint32_t timeout_list = 0x20003148;
    if (fifo_contains(timeout_list, to)) {
        report_detected_triggered("H49"); 
    }
}

void on_bt_att_chan_req_send() {
    report_reached("H50");
    uint32_t buf = frb_mem_read(reg_state[4] + 0x10, 4);

    if (buf == 0) {
        report_detected_triggered("H50");
    } 
}

void on_cmd_data_index() {
    report_reached("H51");
    if (reg_state[0] >= 2) {
        report_detected_triggered("H51");
    }

}

context_struct context_array[] = {
    {0x0000affc, on_semapore_init},
    {0x00002cf4, bt_init},
    {0x00003648, BUG_H32},
    {0x00007248, use_sem_before_init},
    {0x000076ec, on_timeout_callback},
    {0x000035c4, on_tx_free},
    {0x0000a61e, on_net_buf_simple_push},
    {0x00007574, on_z_add_timeout},
    {0x0000b0fe, on_k_delayed_work_init},
    {0x00002cce, on_le_init_check_1},
    {0x00002dc2, on_le_init_check_2},
    {0x00007248, on_le_init_sem_take},
    {0x00001914, on_isr_state_enter},
    {0x00001b28, on_isr_state_exit},
    {0x0000599a, on_net_buf_alloc_len_ret_check_nullptr_in_isr},
    {0x0000345e, on_bt_buf_get_cmd_complete_sent_cmd_reuse},
    {0x0000a58a, on_net_buf_put_check_rx_tx_fifo_state},
    {0x0000233c, on_bt_hci_cmd_send_sync_set_valid},
    {0x00002390, on_bt_hci_cmd_send_sync_set_invalid},
    {0x00002192, on_bt_hci_cmd_done_check_sema_validity},
    {0x00002584, on_set_le_adv_enable_legacy_send_sync},
    {0x00002162, on_hci_cmd_done_state_update},
    {0x00001748, on_arch_swap_enter},
    {0x0000177c, on_z_arm_pendsv},
    {0x00001768, on_arch_swap_after_pendsv},
    {0x0000ade2, on_k_queue_get_poll},
    {0x000099ec, on_bt_att_sent},
    {0x000043a2, on_bt_att_recv},
    {0x000043a4, on_bt_att_recv},
    {0x000043da, on_bt_att_recv},
    {0x000099a2, on_bt_att_status},
    {0x000027f2, on_conn_auto_initiate_call_work_submit},
    {0x00003940, on_bt_conn_add_le_work_init},
    {0x0000993c, on_bt_att_chan_req_send},
    {0x0000214e, on_cmd_data_index},
    {0x000022ca, on_cmd_data_index},
    {0x0000233c, on_cmd_data_index},
    {0x00002584, on_cmd_data_index}
};

void send_context_struct(const context_struct **arr, size_t *size) {
    semaphores[sem_count] = 0x20002f98;
    sem_count++;
    *arr = context_array;
    *size = sizeof(context_array) / sizeof(context_array[0]);
}
