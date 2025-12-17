#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

use icicle_vm::cpu::mem::perm;

include!(concat!(env!("OUT_DIR"), "/firmrebugger.rs"));

/// Safety: the `vm.cpu` pointer must be valid for the lifetime of the emulator.
pub unsafe fn init_config(vm: &mut icicle_vm::Vm) {
    unsafe {
        let emu_data = Box::leak(Box::new(CrashLoggerEmu {
            cpu: (vm.cpu.as_mut() as *mut icicle_vm::cpu::Cpu).cast(),
            reg_read: Some(firmrebugger_reg_read),
            mem_read: Some(firmrebugger_mem_read),
            mem_write: Some(firmrebugger_mem_write),
            add_hook: Some(firmrebugger_add_hook),
        }));
        firmrebugger_init_config((vm as *mut icicle_vm::Vm).cast(), emu_data);
    }
}

unsafe extern "C" fn firmrebugger_reg_read(
    data: EmuData,
    reg_name: *mut std::os::raw::c_char,
) -> u32 {
    let cpu = &mut *data.cast::<icicle_vm::cpu::Cpu>();

    let reg_name = std::ffi::CStr::from_ptr(reg_name).to_str().unwrap();
    let var = cpu.arch.sleigh.get_reg(reg_name).unwrap().var;
    cpu.read_reg(var) as u32
}

unsafe extern "C" fn firmrebugger_mem_read(
    data: EmuData,
    address: u64,
    bytes: *mut u8,
    len: u32,
) -> u32 {
    let cpu = &mut *data.cast::<icicle_vm::cpu::Cpu>();
    let buf = std::slice::from_raw_parts_mut(bytes, len as usize);

    let _ = cpu.mem.read_bytes(address, buf, perm::NONE);

    0
}

unsafe extern "C" fn firmrebugger_mem_write(
    data: EmuData,
    address: u64,
    buf_ptr: *mut u8,
    buf_len: u32,
) -> u32 {
    let cpu = &mut *data.cast::<icicle_vm::cpu::Cpu>();
    let buffer = std::slice::from_raw_parts(buf_ptr, buf_len as usize);

    let _ = cpu.mem.write_bytes(address, buffer, perm::NONE);

    0
}

unsafe extern "C" fn firmrebugger_add_hook(
    vm: *mut std::ffi::c_void,
    emu: *mut CrashLoggerEmu,
    context: context_struct,  
    callback: firmrebugger_callback,
) {
    let vm: *mut icicle_vm::Vm = vm.cast();
    let callback = callback.unwrap();

    (&mut *vm).hook_address(context.address as u64, move |_, _| {
        (callback)(emu, context);
    });
}