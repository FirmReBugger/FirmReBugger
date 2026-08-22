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

typedef struct {
  bool hit;
} MtuSetup;

typedef struct {
  bool invalid_init;
} LeInit;

typedef struct {
  int depth;
} IsrState;

typedef struct {
  bool bug;
  bool is_buf_handed_out_when_in_tx_fifo;
} SentCmdState;

typedef struct {
  bool valid;
  uint32_t head;
  uint32_t tail;
} SemaState;

typedef struct {
  int state;
  int state_target;
} CmdData;

typedef struct {
  bool bug;
  bool pendsv;
} ArchSwap;

MtuSetup mtu_setup = {false};
LeInit le_init = {false};
IsrState isr_state = {0};
SentCmdState sent_cmd_state = {false, false};
SemaState send_sync_sema_states[2] = {{false, 0, 0}, {false, 0, 0}};
CmdData cmd_data[2] = {{0, 0}, {0, 0}};
ArchSwap arch_swap = {false, false};

#define MAX_SEMAPHORES 1000
uint32_t semaphores[MAX_SEMAPHORES];
int sem_count = 0;

// Functions

void on_bt_init() { mtu_setup.hit = true; }

void on_semaphore_init() {
  // GENERIC-invalid-sem-init
  report_reached("H35");
  uint32_t sem = reg_state[0];
  uint32_t initial_count = reg_state[1];
  uint32_t limit = reg_state[2];

  if (sem_count >= MAX_SEMAPHORES) {
    printf("Error: Maximum semaphore count exceeded.\n");
    return;
  }

  semaphores[sem_count] = sem;
  sem_count++;

  if (limit == 0 || initial_count > limit) {
    le_init.invalid_init = true;
    report_detected_triggered("H35");
  }
}

void on_CVE_2021_3329() {
  report_reached("FW54");
  uint32_t sem = 0x20002f7c;
  bool init = false;

  for (int i = 0; i < sem_count; i++) {
    if (semaphores[i] == sem) {
      init = true;
      break;
    }
  }

  if (mtu_setup.hit && !init) {
    report_detected_triggered("FW54");
  }
}

void on_z_impl_k_sem_take() {
  // GENERIC-sem-not-init
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

void on_isr_state_enter() { isr_state.depth += 1; }
void on_isr_state_exit() { isr_state.depth -= 1; }

void on_net_buf_alloc_len_ret_check_nullptr_in_isr() {
  // new-Bug-hci_prio_event_alloc_err_handling
  report_reached("H43");
  // check mtu_setup.hit?
  if (isr_state.depth > 0) {
    uint32_t buf = reg_state[4];
    uint32_t to = reg_state[6];
    uint32_t K_FOREVER = 0xffffffff;

    if (to == K_FOREVER && buf == 0) {
      report_detected_triggered("H43");
    }
  }
}

bool fifo_contains(uint32_t fifo_addr, uint32_t buf) {
  uint32_t next = fifo_addr;
#define MAX_NODES 1000
  uint32_t nodes[MAX_NODES];
  int node_count = 0;

  while (next != 0) {
    for (int i = 0; i < node_count; i++) {
      if (nodes[i] == next) {
        return false;
      }
    }

    if (node_count < MAX_NODES) {
      nodes[node_count++] = next;
    } else {
      printf("Error: Maximum node count exceeded in fifo_contains.\n");
      return false;
    }

    if (next == buf) {
      return true;
    }

    next = frb_mem_read(next, 4);
  }

  return false;
}

void on_bt_buf_get_cmd_complete_sent_cmd_reuse() {
  uint32_t tx_fifo = 0x20003038;

  uint32_t sent_cmd_netbuf = reg_state[4];

  if (fifo_contains(tx_fifo, sent_cmd_netbuf)) {
    sent_cmd_state.is_buf_handed_out_when_in_tx_fifo = true;
  }
}

void on_net_buf_put_check_rx_tx_fifo_state() {
  // new-Bug-sent_cmd_shared_ref_race
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
  // new-Bug-hci-send_sync-dangling-sema-ref
  report_reached("H45");
  uint32_t GLOBAL_cmd_data_0_sync = 0x20000294 + 8;
  uint32_t CMD_DATA_SIZE = 0xc;
  uint32_t net_buf_id = reg_state[0];

  if (net_buf_id == 0 || net_buf_id == 1) {
    if (!send_sync_sema_states[net_buf_id].valid) {
      uint32_t sema_ptr_addr =
          GLOBAL_cmd_data_0_sync + net_buf_id * CMD_DATA_SIZE;

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

void on_arch_swap_enter() { arch_swap.pendsv = false; }
void on_z_arm_pendsv() { arch_swap.pendsv = true; }
void on_arch_swap_after_pendsv() {
  if (!arch_swap.pendsv) {
    arch_swap.bug = true;
  }
}

void on_k_queue_get_poll() {
  // https://github.com/zephyrproject-rtos/zephyr/commit/99c2d2d0
  // https://github.com/zephyrproject-rtos/zephyr/commit/b173e4353fe55c42ee7f77277e13106021ba5678
  // fixed-Bug-k_poll-race-condition
  //
  // CORRECTED 2026-07-14 (was a no-op check -- see bug_analysis/bugs/H47.md):
  // the original hook (0x0000ade2) sits inside k_queue_poll()'s post-k_poll()
  // re-check of the queue (kernel/queue.c:320-321 in v2.2.0), reached only
  // via the fallthrough of a `cbz r0` on the SAME register this function
  // then re-read as "node" -- i.e. the old predicate (node==0) was true by
  // construction every single time this address was hit at all (confirmed
  // live: 75,775 triggers, zero correlated crashes). It never distinguished
  // anything.
  //
  // The actual race the linked commits describe is k_poll()'s non-atomic
  // unlock-then-block: it can report success (or -EAGAIN, "try again")
  // while another context's insert+wakeup is lost, so the subsequent
  // locked re-check of queue->data_q.head still finds nothing. That
  // specific combination -- k_poll() claimed something changed
  // (err == 0), yet the queue is still empty -- is the actual signature of
  // the race, and it's checkable one instruction earlier, at the `err`
  // decision point (kernel/queue.c:309, `err = k_poll(...)`), where
  // reg_state[0] is confirmed live to be k_poll()'s return value and
  // reg_state[5] the queue pointer (data_q.head is the queue struct's
  // first word).
  report_reached("H47");
  uint32_t other_bug = arch_swap.bug || sent_cmd_state.bug;
  uint32_t poll_err = reg_state[0];
  uint32_t queue = reg_state[5];
  uint32_t data_q_head = frb_mem_read(queue, 4);

  if (poll_err == 0 && data_q_head == 0 && !other_bug) {
    report_detected_triggered("H47");
  }
}

void on_le_init_check_1() {
  uint32_t rsp_ptr_ptr = reg_state[13] + 4;
  uint32_t buf = frb_mem_read(rsp_ptr_ptr, 4);

  uint32_t data = frb_mem_read(buf + 8, 4);

  uint32_t le_max_len = frb_mem_read(data + 1, 2);
  uint32_t le_max_num = frb_mem_read(data + 3, 1);

  if (le_max_len != 0 && le_max_num == 0) {
    le_init.invalid_init = true;
  }
}

void on_le_init_check_2() {
  uint32_t rsp_ptr_ptr = reg_state[13] + 4;
  uint32_t buf = frb_mem_read(rsp_ptr_ptr, 4);

  uint32_t data = frb_mem_read(buf + 8, 4);

  uint32_t acl_max_num = frb_mem_read(data + 4, 2);

  if (acl_max_num == 0) {
    le_init.invalid_init = true;
  }
}

void on_le_init_sem_take() {
  // new-Bug-invalid-init-le_read_buffer_size
  report_reached("H42");
  uint32_t LE_INIT_SEM = 0x20002F7C;
  uint32_t sem = reg_state[0];
  if (sem == LE_INIT_SEM && le_init.invalid_init) {
    report_detected_triggered("H42");
  }
}

void on_timeout_callback() {
  // GENERIC-invalid_timeout_callback
  report_reached("H34");
  uint32_t t = reg_state[0];
  uint32_t callback = frb_mem_read(t + 0xc, 4);
  if (callback == 0) {
    report_detected_triggered("H34");
  }
}

void on_bt_att_sent() {
  // fixed-Bug-bt_att-resp-timeout-null-ptr
  // https://github.com/zephyrproject-rtos/zephyr/commit/577cd82#diff-3adc165d775d407a3eb6b90da365671eee38ca4e38d9b6f6661abf2975a5161eR2441
  report_reached("H48");
  uint32_t att = reg_state[6];
  if (att == 0) {
    report_detected_triggered("H48");
  }
}

void on_bt_att_recv() {
  // fixed-Bug-bt_att-resp-timeout-null-ptr
  // https://github.com/zephyrproject-rtos/zephyr/commit/577cd82#diff-3adc165d775d407a3eb6b90da365671eee38ca4e38d9b6f6661abf2975a5161eR2441
  report_reached("H48");
  uint32_t att_chan = reg_state[6];
  uint32_t att = frb_mem_read(att_chan, 4);
  if (att == 0) {
    report_detected_triggered("H48");
  }
}

void on_bt_att_status() {
  // fixed-Bug-bt_att-resp-timeout-null-ptr
  // https://github.com/zephyrproject-rtos/zephyr/commit/577cd82#diff-3adc165d775d407a3eb6b90da365671eee38ca4e38d9b6f6661abf2975a5161eR2441
  report_reached("H48");
  uint32_t ch = reg_state[0];
  uint32_t att_chan = ch - 4;
  uint32_t att = frb_mem_read(att_chan, 4);

  if (att == 0) {
    report_detected_triggered("H48");
  }
}

void on_conn_auto_initiate_call_work_submit() {
  // fixed-Bug-bt-periph-update_conn_param-work-double-submit
  // https://github.com/zephyrproject-rtos/zephyr/commit/77b11d6
  report_reached("H49");
  uint32_t STRU_OFF_conn_to_update_work = 0x50;
  uint32_t STRU_OFF_work_to_timeout = 0xC;
  uint32_t conn = reg_state[4];

  uint32_t update_work = conn + STRU_OFF_conn_to_update_work;
  uint32_t to = update_work + STRU_OFF_work_to_timeout;

  uint32_t timeout_list = 0x20003148;
  if (fifo_contains(timeout_list, to)) {
    report_detected_triggered("H49");
  }
}

void on_bt_conn_add_le_work_init() {
  // fixed-Bug-bt-periph-update_conn_param-work-double-submit
  // https://github.com/zephyrproject-rtos/zephyr/commit/77b11d6
  report_reached("H49");
  uint32_t STRU_OFF_conn_to_update_work = 0x50;
  uint32_t STRU_OFF_work_to_timeout = 0xC;
  uint32_t conn = reg_state[4];

  uint32_t update_work = conn + STRU_OFF_conn_to_update_work;
  uint32_t to = update_work + STRU_OFF_work_to_timeout;

  uint32_t timeout_list = 0x20003148;
  if (fifo_contains(timeout_list, to)) {
    report_detected_triggered("H49");
  }
}

void on_k_delayed_work_init() {
  // GENERIC-delayed_work_init-double-add
  report_reached("H40");
  // GENERIC-delayed_work_init-sys_dnode_is_linked
  report_reached("H39");
  uint32_t work = reg_state[0];
  uint32_t STRU_OFF_work_to_timeout = 0xC;
  uint32_t timeout = work + STRU_OFF_work_to_timeout;

  uint32_t timeout_list = 0x20003148;
  if (fifo_contains(timeout_list, timeout)) {
    report_detected_triggered("H40");
  }

  uint32_t next = frb_mem_read(timeout, 4);
  if (next != 0) {
    report_detected_triggered("H39");
  }
}

void on_z_add_timeout() {
  // GENERIC-add_timeout-double-add
  report_reached("H38");
  // GENERIC-add_timeout-sys_dnode_is_linked
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

void on_tx_free() {
  // GENERIC-invalid-tx_free
  report_reached("H36");
  uint32_t tx = reg_state[0];
  if ((tx & 0xff) == 0x02) {
    report_detected_triggered("H36");
  }
}

void on_set_le_adv_enable_legacy_send_sync() {
  uint32_t index = reg_state[0];
  uint32_t state = reg_state[13] + 4;

  uint32_t target = frb_mem_read(state, 4);

  if (index >= 2) {
    return;
  }
  cmd_data[index].state = state;
  cmd_data[index].state_target = target;
}

void on_hci_cmd_done_state_update() {
  // new-Bug-hci-send_sync-dangling-conn-state-ref
  report_reached("H46");
  uint32_t index = reg_state[0];
  if (index >= 2) {
    return;
  }

  uint32_t GLOBAL_cmd_data_0_state = 0x20000294 + 4;
  uint32_t CMD_DATA_SIZE = 0xC;
  uint32_t cmd_data_ptr = GLOBAL_cmd_data_0_state + (CMD_DATA_SIZE * index);

  uint32_t state = frb_mem_read(cmd_data_ptr, 4);

  if (state != 0) {
    uint32_t target = frb_mem_read(state, 4);
    if (target != cmd_data[index].state_target) {
      report_detected_triggered("H46");
    }
  }
}

void on_bt_att_chan_req_send() {
  // fixed-Bug-double-bt_att_chan_req_send-null-ptr
  //
  // VERIFIED 2026-07-14 (see bug_analysis/bugs/H50.md): the hook/predicate
  // are both correct as written (req+0x10 is req->buf, confirmed via
  // DWARF; this really is att_send_req's entry, where req->buf gets
  // dereferenced unconditionally a few instructions later) -- this is NOT
  // a tautological/broken check like the original H47 was. It never
  // fires in THIS build because CONFIG_BT_SMP is not compiled in (checked
  // both FirmBench and FirmBenchX), which is the only path that resends a
  // request whose req->buf was already nulled by a prior failed send
  // (att_error_rsp's security-retry branch, hci_core.c/att.c). Every real
  // invocation of att_send_req in this build (att_process's list-pop,
  // bt_att_req_send's direct call) always uses a request whose buf was
  // just freshly populated, and att_handle_rsp unconditionally destroys
  // and NULLs the outstanding request before ever processing the next
  // one -- so there is no live "double call" path to hit. Left as-is
  // (not deleted) since a build with CONFIG_BT_SMP enabled could still
  // exercise the real historical bug this checks for.
  report_reached("H50");
  uint32_t req = reg_state[4];
  uint32_t buf = frb_mem_read(req + 0x10, 4);

  if (buf == 0) {
    report_detected_triggered("H50");
  }
}

void on_cmd_data_index() {
  // GENERIC-cmd_data-oob-index
  report_reached("H51");
  uint32_t index = reg_state[0];
  if (index >= 2) {
    report_detected_triggered("H51");
  }
}

uint32_t net_buf_simple_headroom(uint32_t buf) {
  if (buf == 0) {
    return 0;
  }

  uint32_t buf_data = frb_mem_read(buf, 4);
  uint32_t buf__buf = frb_mem_read(buf + 8, 4);
  return buf_data - buf__buf;
}

void on_net_buf_simple_push() {
  // GENERIC-net_buf_simple_push-underflow
  report_reached("H37");
  uint32_t buf = reg_state[0];
  uint32_t len = reg_state[1];

  if (net_buf_simple_headroom(buf) < len) {
    report_detected_triggered("H37");
  }
}

void z_fatal_error() {
  report_reached("ERROR-Bug-z_fatal_error");
  report_detected_triggered("ERROR-Bug-z_fatal_error");
}

void register_reflection_points() {
    frb_add_reflection_point(0x0000affc, on_semaphore_init);
    frb_add_reflection_point(0x00002cf4, on_bt_init);
    frb_add_reflection_point(0x00003648, on_CVE_2021_3329);
    frb_add_reflection_point(0x00007248, on_z_impl_k_sem_take);
    frb_add_reflection_point(0x000076ec, on_timeout_callback);
    frb_add_reflection_point(0x000035c4, on_tx_free);
    frb_add_reflection_point(0x0000a61e, on_net_buf_simple_push);
    frb_add_reflection_point(0x00007574, on_z_add_timeout);
    frb_add_reflection_point(0x0000b0fe, on_k_delayed_work_init);
    frb_add_reflection_point(0x00002cce, on_le_init_check_1);
    frb_add_reflection_point(0x00002dc2, on_le_init_check_2);
    frb_add_reflection_point(0x00007248, on_le_init_sem_take);
    frb_add_reflection_point(0x00001914, on_isr_state_enter);
    frb_add_reflection_point(0x00001b28, on_isr_state_exit);
    frb_add_reflection_point(0x0000599a, on_net_buf_alloc_len_ret_check_nullptr_in_isr);
    frb_add_reflection_point(0x0000345e, on_bt_buf_get_cmd_complete_sent_cmd_reuse);
    frb_add_reflection_point(0x0000a58a, on_net_buf_put_check_rx_tx_fifo_state);
    frb_add_reflection_point(0x0000233c, on_bt_hci_cmd_send_sync_set_valid);
    frb_add_reflection_point(0x00002390, on_bt_hci_cmd_send_sync_set_invalid);
    frb_add_reflection_point(0x00002192, on_bt_hci_cmd_done_check_sema_validity);
    frb_add_reflection_point(0x00002584, on_set_le_adv_enable_legacy_send_sync);
    frb_add_reflection_point(0x00002162, on_hci_cmd_done_state_update);
    frb_add_reflection_point(0x00001748, on_arch_swap_enter);
    frb_add_reflection_point(0x0000177c, on_z_arm_pendsv);
    frb_add_reflection_point(0x00001768, on_arch_swap_after_pendsv);
    frb_add_reflection_point(0x0000adb8, on_k_queue_get_poll);  // corrected from 0x0000ade2 -- see H47.md
    frb_add_reflection_point(0x000099ec, on_bt_att_sent);
    frb_add_reflection_point(0x000043a2, on_bt_att_recv);
    frb_add_reflection_point(0x000043a4, on_bt_att_recv);
    frb_add_reflection_point(0x000043da, on_bt_att_recv);
    frb_add_reflection_point(0x000099a2, on_bt_att_status);
    frb_add_reflection_point(0x000027f2, on_conn_auto_initiate_call_work_submit);
    frb_add_reflection_point(0x00003940, on_bt_conn_add_le_work_init);
    frb_add_reflection_point(0x0000993c, on_bt_att_chan_req_send);
    frb_add_reflection_point(0x0000214e, on_cmd_data_index);
    frb_add_reflection_point(0x000022da, on_cmd_data_index);
    frb_add_reflection_point(0x0000233c, on_cmd_data_index);
    frb_add_reflection_point(0x00002584, on_cmd_data_index);
    frb_add_reflection_point(0x0000aad2, z_fatal_error);
}
