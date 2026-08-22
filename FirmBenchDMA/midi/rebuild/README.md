# Rebuilding MIDI-Synthesizer

```sh
./build.sh --verify
```

The checked-in ELF was built for STM32F429ZI with GNU Arm 7-2018-q2 at `-O0`.
DICE's later source comments out `MIDIMsg_free(msg)` in `MIDI_note_on_do`, but
the benchmark machine code calls `free` at the end of both note callbacks.
The local patch restores that intentional double-free/use-after-free condition.

The recipe also preserves the recovered System Workbench link order. The
result has entry point `0x08001c3d`, size `text=9948 data=2144 bss=19012`, and
matches every loadable byte of `../MIDI-Synthesizer.elf`. The ELF's whole-file
SHA-256 is `dc1333b714bfc62fe87ed2150859112b8390693232a975d36d7dbe882d969356`;
whole-file reproduction is not expected because its DWARF records a historical
Windows workspace path.
