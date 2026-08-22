# FirmReBugger

A benchmark framework for monolithic firmware fuzzers.
![alt text](report.png)

## Raven Creation

We have made the process of incorporating a bug with a Raven, simple—we demonstrate the ease with which Ravens can be constructed using three case examples of common bug types:

- [Stack Buffer Overflow](#stack-buffer-overflow)
- [Type Confusion](#type-confusion)
- [Dangling Pointer](#danling-pointer)

## Full Paper Results

The full table of our experiemnts are detailed in `paper_results`

- [FirmBench](paper_results/FirmBench.pdf)
- [FirmBenchDMA](paper_results/FirmBenchDMA.pdf)
- [FirmBenchX](paper_results/FirmBenchX.pdf)

## Quick Start

### Set up

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
sudo sh -c 'echo 524288 > /proc/sys/fs/inotify/max_user_watches && echo 8192 > /proc/sys/fs/inotify/max_user_instances'
```

### Requirements

```bash
Install uv https://docs.astral.sh/uv/getting-started/installation/
Install docker https://docs.docker.com/engine/install
sudo apt-get install automake texinfo unzip
sudo apt install gcc-arm-none-eabi
sudo apt install texlive-latex-base
sudo apt install texlive-xetex texlive-fonts-recommended texlive-latex-extra
install node (node >= 22.0.0)
```

### Use prebuilt Docker images (Recommended)

If you're having trouble building the fuzzers locally or do not need to, you can pull our prebuilt images from GHCR:

```bash
uv run frb build --use-prebuilt
```

This pulls registry images and tags them locally as `frb:<fuzzer>` and `frb_original:<fuzzer>`, which are the names used by fuzzing/triage runtime.

### Building Fuzzer Dockers locally (Optional)

If the prebuilt images fail to run on your system, fall back to the non-prebuilt images with:

```bash
git clone https://github.com/FirmReBugger/FirmReBugger
cd FirmReBugger
export FIRMREBUGGER_BASE_DIR=$(pwd)
# Follow the steps and build all fuzzers
uv run frb build
# If a fuzzer fails to build, retry building it individually.
```

### Starting the Web Application (Recommended)

It is recommneded to run FirmReBugger through the webapp

```bash
# Run the webapp
uv run frb app --help
uv run frb app -p <port>

# By default the app binds to 127.0.0.1 (localhost only).
# If you are connecting from a remote machine over SSH, forward the port to your
# local browser (adjust the port to match the -p value you used above):
ssh -L <port>:localhost:<port> user@remote-host
# Then open http://localhost:<port> in your local browser

# If you want/need to rebuild the front end
cd src/firmrebugger-web
npm install
npm run build
```

**Report** shows you a summary of your fuzzing campaigns with FirmReBugger.

**Job manager** lets you schedule jobs (Triaging or Fuzzing) all automatically.

![alt text](job_manager.png)

### Recommended Workflow

1. Launch the web application by following the instructions provided above. e.g. `uv run frb app`

2. Navigate to the **Job Manager** tab to configure and schedule fuzzing jobs.

3. If auto-triaging is enabled, the backend scheduler will automatically queue triaging jobs once fuzzing completes. Otherwise, you can manually start triaging from the **Finished Jobs** section.

4. Once triaging jobs are completed, go to the **Report** tab to configure, analyze and visualize the outcomes.

### Workflow CLI

```bash
cd FirmReBugger
export FIRMREBUGGER_BASE_DIR=$(pwd)
# Fuzz your choice of binaries with
uv run frb fuzz -h

# Bind-mount your local FirmReBugger source for live updates in containers
# (keeps you from rebuilding images for bug-analyzer changes)
docker run -it \
  --mount type=bind,source=./,target=/benchmark \
  --mount type=bind,source=$(pwd)/src,target=/home/user/firmrebugger/src \
  frb:<fuzzer> /bin/bash

# Run the bug-analyzer
cd <to_results_folder>
uv run frb bug-analyzer <fuzzing_results_dir> <descriptor_path>

# Visualize the data
uv run frb charting-tool
```

### Trouble shooting

- If fuzzing sessions die prematurely, check the logs at:

```
$FIRMREBUGGER_BASE_DIR/outputs/<run_name>/<benchmark>-<binary>-<fuzzer>/fuzzing_logs/
```

- If FirmReBugger refuses to start with an error about an old directory
  layout, your checkout still has data from before the folder structure
  changed (see [Folder Structure](#folder-structure)). Migrate it in place:

  ```bash
  uv run frb port-layout --dry-run   # preview what would move
  uv run frb port-layout             # apply it
  ```

#### Commands

```bash
cd FirmReBugger
export FIRMREBUGGER_BASE_DIR=$(pwd)
uv run frb --help
uv run frb fuzz --help
uv run frb build --help
uv run frb bug-analyzer --help
uv run frb charting-tool --help
uv run frb port-layout --help
uv run frb app --help
```

## Contributing to FirmReBugger

### Adding a New Fuzzer

To integrate a new fuzzer into FirmReBugger:

1. Docker Integration

   Add your fuzzer under the docker/ directory:
   - An original image for fuzzing.

   - A **FRB-patched** version for triaging (i.e., including the FirmReBugger modifications). Follow the structure and integration pattern used by the existing fuzzers as a reference.

2. Runner Implementation

   Implement a corresponding runner at:

   ```
   Fuzzers/<your_fuzzer>/runner.sh
   ```

   This runner defines how FirmReBugger invokes your fuzzer inside Docker.

3. Benchmark Configuration

   For each binary you want to support, add your fuzzer configuration under:

   ```
   <Benchmark>/<Binary>/<your_fuzzer>/
   ```

   Include all required configuration files, scripts, and auxiliary resources.
   To override the runner for a specific target, drop a `runner.sh` directly
   in this folder — it takes priority over `Fuzzers/<your_fuzzer>/runner.sh`.

4. Results Analyzer

   Implement a results parser at:

   ```
   Fuzzers/<your_fuzzer>/analyzer.py
   ```

   exposing a function named `analyze(bench_info, output, run_data, Crash, run_name, descriptor_path)`
   that returns `(run_data, time_list)`. The bug-analyzer discovers this file by
   fuzzer name, so nothing elsewhere needs to be registered. If your fuzzer's
   output format matches an existing one, this file can just re-export it, e.g.:

   ```python
   from firmrebugger.bug_analyzer_utils.fuzzware_analyzer import fuzzware_analyzer as analyze
   ```

5. Optional Metadata

   Drop a `Fuzzers/<your_fuzzer>/fuzzer.yml` if you need either of these
   (both are optional and omitted by default):

   ```yaml
   bug_prefix:
     XY # short prefix used for this fuzzer's bug IDs (e.g. FW01),
     # shown in `frb bug-registry`'s "next free ID" table
   bind_mount:
     true # bind-mount the output dir into the container instead of
     # docker-cp'ing it in/out — use this if your fuzzer needs to
     # stream output live or has baked-in absolute host paths
   ```

During execution, FirmReBugger automatically:

- Creates the fuzzing output directory.

- Copies the required configuration files.

- Copies the appropriate fuzzer runner.

- Launches the fuzzer inside the corresponding Docker container.

- Picks up your `analyzer.py` and `fuzzer.yml` (if present) by fuzzer name — no other file in the repo needs to be touched.

### Extending existing Ravens

If you discover a new bug and want to extend an existing Raven:

- Modify the corresponding `bug_descriptor.c` file located in the relevant binary's directory.

- Follow the structure and conventions used in existing descriptors.

- If your introspection point address is symbol-based, use `frb_symbolize("symbol_name", offset)` to resolve it at runtime from the binary's `symbols.txt` file. If the address is fixed, pass it directly to `frb_add_reflection_point`.

### Adding a New Binary and Its Corresponding Raven

1. Choose a benchmark suite (FirmBench, FirmBenchDMA, or FirmBenchX) and create a new folder named after your binary:

```
<Benchmark>/<Binary>/
```

2. Add the ELF directly in that folder.

3. Add the Raven implementation in:

```
<Benchmark>/<Binary>/bug_descriptor.c
```

4. Follow the existing directory structure for fuzzers:

```
<Benchmark>/<Binary>/<fuzzer>/
```

Maintaining consistency with the existing structure ensures compatibility with the scheduling, fuzzing, and triaging pipelines. Fuzzing/triaging output is never stored here — it's written under the top-level `outputs/` tree (see Folder Structure below).

## Folder Structure

```
FirmReBugger/
├── docker/
├── Fuzzers/
│   └── <Fuzzer>/
│       ├── runner.sh
│       ├── analyzer.py
│       └── fuzzer.yml (optional)
├── FirmBench/
│   └── <Binary>/
│       ├── <Binary's ELF file>
│       ├── bug_descriptor.c
│       └── <Fuzzer>/
│           └── config.yml
├── FirmBenchDMA/
├── FirmBenchX/
├── outputs/
│   └── <run_name>/
│       └── <Benchmark>-<Binary>-<Fuzzer>/
│           ├── frb_info.json
│           ├── frb_report.json
│           ├── fuzzing_logs/
│           └── 01-output/, 02-output/, ...
├── pyproject.toml
├── README.md
├── requirements.txt
├── src/
│   ├── firmrebugger/
│   │   ├── analysis_bench/
│   │   ├── bug_analyzer/
│   │   ├── build_fuzzers/
│   │   ├── charting_tools/
│   │   ├── fuzz/
│   │   ├── utils/
│   │   ├── __init__.py
│   │   └── main.py
│   └── firmrebugger-web/
├── uv.lock
```

## Raven API

Every `bug_descriptor.c` starts with the same standard header:

```c
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
```

Reflection points are registered in a single `register_reflection_points()` function using `frb_add_reflection_point`. Addresses can be hardcoded or resolved at runtime from `symbols.txt` using `frb_symbolize(symbol_name, offset)`:

```c
void register_reflection_points() {
    // Fixed address
    frb_add_reflection_point(0x08004f8a, INTROSPECTION_FW11);
    // Symbol-relative address (resolved from symbols.txt at runtime)
    frb_add_reflection_point(frb_symbolize("printFloat", 0x1b2), INTROSPECTION_FW11);
}
```

Available API functions:

| Function                                | Description                                                               |
| --------------------------------------- | ------------------------------------------------------------------------- |
| `reg_state[0..15]`                      | Current ARM register values (r0–pc) at the reflection point               |
| `frb_mem_read(addr, size)`              | Read `size` bytes from emulated memory at `addr`                          |
| `frb_mem_write(addr, value, size)`      | Write `value` of `size` bytes to emulated memory at `addr`                |
| `frb_report_reached(bug_id)`            | Mark bug as reached (first time only)                                     |
| `frb_report_detected_triggered(bug_id)` | Mark bug as triggered/detected (first time only)                          |
| `frb_symbolize(symbol, offset)`         | Resolve `symbol` from `symbols.txt` and add `offset` (Thumb bit stripped) |
| `frb_add_reflection_point(addr, fn)`    | Register an introspection function at `addr`                              |
| `frb_print_regs()`                      | Print all registers to stdout (debugging)                                 |

## Raven Examples

### Stack Buffer Overflow

**Stack Buffer Overflow** occurs when data written to a buffer on the stack exceeds its allocated size, potentially corrupting adjacent memory. By introspecting buffer boundaries, sizes, and index calculations—along with placing unique reflection points—it is possible to identify buffer overflow bugs, as demonstrated in the following example.

```c
// Introspection point: FW11 - Stack buffer overflow in printFloat
void INTROSPECTION_FW11() {
    report_reached("FW11");
    if (reg_state[2] > 9) {
        report_detected_triggered("FW11");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(frb_symbolize("settings_store_global_setting", 0x1b2), INTROSPECTION_FW11);
}
```

_Listing: Stack buffer overflow example. A Raven crafted for bug "FW11" in the `CNC` target binary from P2IM._

The listing above shows a Raven that captures a real-world stack buffer overflow (Bug ID: FW11) in the `CNC` binary, originally identified by Fuzzware. The vulnerability occurs in the `printFloat` function, where user-controlled input sets the value of `settings.decimal_places`. This value is later used as an index into a stack-allocated buffer of size 10. Without bounds checking, values greater than 9 cause a stack buffer overflow.

The Raven registers a reflection point via `frb_symbolize`, resolving the hook address from `symbols.txt` at runtime rather than hardcoding it. At the hooked location, the buffer index (`settings.decimal_places`) is held in register `R2`. By checking if the value in `R2` is greater than 9, the Raven precisely captures the triggering condition for this stack buffer overflow bug.

### Type Confusion

**Type Confusion** arises when a program erroneously interprets an incorrect type for a region of memory. As a consequence, the program may access fields, invoke functions, or perform operations that are invalid for the underlying data, leading to undefined behavior. Introspection of object types and pointer usage can help identify type confusion bugs.

An illustrative example of a Raven is shown in the code below, based on the bug ID `MF04` reported by MultiFuzz in the **Zephyr SocketCAN** binary. In Zephyr's device model, each device is represented by a struct containing a pointer named `driver_api`. This pointer references a table of function pointers that define the operations supported by the device's driver, such as configuration or data transmission.

```c
void INTROSPECTION_MF04() {
    report_reached("MF04");
    // canbus fail to verify device type
    uint32_t read_addr = reg_state[0] + 0x4;
    if (frb_mem_read(read_addr, 4) != 0x0800f7e4) {
        report_detected_triggered("MF04");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x08005e28, INTROSPECTION_MF04);
}
```

The CAN bus subcommands allow users to specify a target device for command execution. At runtime, the target device is resolved using the `z_impl_device_get_binding` function, which returns a pointer to a generic device struct. However, no type verification is performed to ensure that the selected device implements the CAN bus API. As a result, if a non-CAN device is specified (such as a GPIO device), the subcommand will erroneously perform CAN bus operations on an incompatible device struct.

### Dangling Pointer

**Dangling Pointer** refers to a pointer that continues to reference freed memory or a stack frame that no longer exists. Dereferencing such pointers in C or C++ is considered undefined behavior and can result in unpredictable or erroneous program states. This is a common issue in manual memory management environments, particularly in C/C++ firmware.

Identifying dangling pointer usage involves combining introspection at points where pointers become invalid with checks at locations where the invalid pointer may later be used.

```c
// Dangling pointer in HAL_I2C_Mem_Read — poison the pointer on return
void INTROSPECTION_HAL_I2C_Mem_Read_ret() {
    report_reached("FW19");
    frb_mem_write(0x200030cc, 0xDEADBEEF, 4);
}

// Check whether the now-invalid pointer is later dereferenced
void INTROSPECTION_check_I2C_MasterReceive_BTF() {
    uint32_t ptr = frb_mem_read(0x200030cc, 4);
    if (ptr == 0xDEADBEEF) {
        report_detected_triggered("FW19");
    }
}

void register_reflection_points() {
    frb_add_reflection_point(0x0800c9b0, INTROSPECTION_HAL_I2C_Mem_Read_ret);
    frb_add_reflection_point(0x0800bd02, INTROSPECTION_check_I2C_MasterReceive_BTF);
}
```

_Listing: Real-world example of a Raven for bug "FW19" in the `Soldering_Iron` binary from P2IM. Here, writes to memory are used to poison a dangling pointer so that any later use is detectable._

The listing above highlights a dangling pointer bug (Bug ID: FW19) identified by Fuzzware in the `Soldering_Iron` binary. The root cause lies in the function `HAL_I2C_Mem_Read`, which assigns a stack-allocated buffer from a higher-level function to the `pBuffPtr` member of a global I2C object. Once the calling function returns, the stack buffer becomes invalid, but the global I2C object continues to reference it.

Later, in another interrupt, `MMA8652FC::getAxisReadings` is called, which invokes `FRToSI2C::Mem_Read` with a temporary stack buffer and its length as arguments. Due to the calling convention, the last two arguments (including the buffer length) are stored on the stack. If a hardware timer interrupt occurs before `HAL_I2C_Mem_Read` is called, the interrupt handler function `I2C_MasterReceive_BTF` writes to the global `pBuffPtr`, which still points to the now-reused stack location. This corrupts the buffer length argument, leading to a stack buffer overflow in `MMA8652FC::getAxisReadings`, which could overwrite the return address and grant arbitrary control over the instruction pointer.

Dangling pointers are particularly hard to detect because a stale pointer might be dereferenced at many locations throughout the program. To facilitate triage, `frb_mem_write` overwrites the pointer with a sentinel value (`0xDEADBEEF`) at the moment it becomes invalid. Any later use of the dangling pointer will then be caught by the second reflection point, making the bug easy to identify.

## Modification table

| REF          | Binary            | Modification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| P2IM         | CNC               | Early return to serial_reset_read_buffer<br>Return HAL_ERROR removed from PLLRDY flag check<br>Early return to delay_ms<br>Early return to delay_us                                                                                                                                                                                                                                                                                                                                                                            |
| P2IM         | Console           | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| P2IM         | Gateway           | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| P2IM         | PLC               | CRC check in Modbus::validateRequest commented out<br>Code in Modbus::poll rewritten to avoid code that waits for specific timeouts.                                                                                                                                                                                                                                                                                                                                                                                           |
| P2IM         | Soldering_Iron    | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| PRETENDER    | RF_Door_Lock      | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| uEmu         | 3DPrinter         | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| uEmu         | GPSTracker        | Delay(2000) removed in setup<br>Delay loop waiting for gsm_power_status removed in gsm_off<br>Delay loop waiting for gsm_power_status removed in gsm_on<br>Maxseconds \* 1000 is changed to just maxsections in gsm_wait_for_reply<br>Delay(1000) removed in gsm_wakeup<br>Delay(100) removed in gps_on<br>Delay(100) removed in gps_off<br>Multiple calls to delay removed in status_delay<br>Delay(100) removed in blink_got_gps<br>Delay(200) removed in blink_start<br>Calls to efc_perform_command removed in flash_write |
| uEmu         | utasker_USB       | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| uEmu         | utasker_MODBUS    | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| uEmu         | Zephyr_SocketCan  | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| HALucinator  | 6LoWPAN_Receiver  | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| SPLITS       | Contiki_NG_Shell  | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| DICE         | MIDI              | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| DICE         | MODBUS            | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Fuzzware     | Contiki-hello-4-4 | Early return to fade<br>Early return to lpm enter<br>Early return to printf                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Hoedur       | Contiki-hello-4-8 | Early return to fade<br>Early return to lpm enter<br>Early return to printf                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Fuzzware     | Contiki-6lowpan   | Early return to fade<br>Early return to lpm enter<br>Early return to printf                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Hoedur       | Contiki-router    | Early return to fade<br>Early return to lpm enter<br>Early return to printf<br>Early return to platform_idle                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Fuzzware     | Contiki-snmp      | Early return to fade<br>Early return to lpm enter<br>Early return to printf                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Hoedur       | loramac           | Early return to z_arm_mpu_init<br>Early return to arm_core_mpu_configure_dynamic_mpu_regions<br>Early return to arm_core_mpu_configure_static_mpu_regions<br>Early return to z_impl_k_busy_wait<br>Early return to z_impl_k_sleep"<br>Early return to printk                                                                                                                                                                                                                                                                   |
| Hoedur       | gnrc_networking   | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Fuzzware     | Zephyr-3330       | Early return arch_system_halt<br>Early return log_0<br>Early return log_1<br>Early return log_2<br>Early return log_3<br>Early return log_n<br>Early return printk<br>Early return shell_fprintf_fmt<br>Early return z_impl_k_busy_wait<br>Early return z_impl_k_sleep<br>Early return z_tick_sleep<br>Early return z_vprintk<br>Patched ieee802154_reass_timeout<br>Patched spi_sam_flat_read.patch                                                                                                                           |
| Fuzzware     | Zephyr-bt         | Early return arch_system_halt<br>Early return log_0<br>Early return log_1<br>Early return log_2<br>Early return log_3<br>Early return log_n<br>Early return printk<br>Early return shell_fprintf_fmt<br>Early return z_impl_k_busy_wait<br>Early return z_impl_k_sleep<br>Early return z_tick_sleep<br>Early return z_vprintk                                                                                                                                                                                                  |
| Hoedur       | Zephyr-f429zi     | Early return to arch_system_halt<br>Early return to log_0<br>Early return to log_1<br>Early return to log_2<br>Early return to log_3<br>Early return to log_n<br>Early return to printk<br>Early return to shell_fprintf_fmt<br>Early return to z_impl_k_busy_wait<br>Early return to z_impl_k_sleep<br>Early return to z_tick_sleep<br>Early return to z_vprintk                                                                                                                                                              |
| Fuzzware     | Zephyr-nrf        | Patched bluetooth_hci_overlay<br>Patched bt_hci_cmd_timeout<br>Patched bt_hostonly_build<br>Patched stm32f4_cap_flash_region_sizes<br>Patched arm_generic_atomic                                                                                                                                                                                                                                                                                                                                                               |
| Fuzzware     | Zephyr-sam4s      | Early return to arch_system_halt<br>Early return to log_0<br>Early return to log_1<br>Early return to log_2<br>Early return to log_3<br>Early return to log_n<br>Early return to printk<br>Early return to shell_fprintf_fmt<br>Early return to z_impl_k_busy_wait<br>Early return to z_impl_k_sleep<br>Early return to z_tick_sleep<br>Early return to z_vprintk                                                                                                                                                              |
| Fuzzware     | Zephyr-sampro     | Early return to arch_system_halt<br>Early return to log_0<br>Early return to log_1<br>Early return to log_2<br>Early return to log_3<br>Early return to log_n<br>Early return to printk<br>Early return to shell_fprintf_fmt<br>Early return to z_impl_k_busy_wait<br>Early return to z_impl_k_sleep<br>Early return to z_tick_sleep<br>Early return to z_vprintk                                                                                                                                                              |
| MultiFuzz    | RIOT_CCN_LITE     | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| MultiFuzz    | RIOT_GNRC         | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| FirmReBugger | Hoverboard        | Dma patched in DMA1_Channel1_IRQHandler<br>Patched softwareserialRXInterrupt<br>Early return to HAL_Delay<br>Early return to Flash_WaitLastOperation<br>Early return to consoleLog                                                                                                                                                                                                                                                                                                                                             |
| FirmReBugger | Oresat-Control    | Timer patch to chVTDoTickI<br>Patched DMA in ax5043SPIExchange<br>Patched DMA in ax5043GetStatus<br>Early return to Delay                                                                                                                                                                                                                                                                                                                                                                                                      |
| FirmReBugger | BetaFlight        | Early return to FLASH_WaitForLastOperation<br>Early return to OverclockRebootIfNecessar<br>Early return to OTG_FS_IRQHandle<br>Early return to Delay                                                                                                                                                                                                                                                                                                                                                                           |

# Cite as:

```
@inproceedings{2026firmrebugger,
  title={FirmReBugger: A Benchmark Framework for Monolithic Firmware Fuzzers},
  author={Duong, Mathew and Chesser, Michael and Farrelly, Guy and Nepal, Surya and Ranasinghe, Damith C},
  booktitle = {{USENIX} Security Symposium},
  series    = {USENIX Security},
  year      = {2026}
}
```
