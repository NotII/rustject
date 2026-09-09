# rustject

x64 manual-map DLL injector for CS2 (`cs2.exe`), written in Rust.
Single dependency: `windows-sys`. PE parsing is done by hand — no `pelite`, no `goblin`.

## Usage

```
rustject <dll> [-t|--target exe]
```

Defaults to `cs2.exe`. Waits for the target process, manual-maps the DLL,
and runs `DllMain(DLL_PROCESS_ATTACH)` via a small position-independent stub
on a remote thread (`CreateRemoteThread`, `NtCreateThreadEx` fallback).

```
rustject fakevac.dll
rustject fakevac.dll -t notepad.exe
```

Exit code is `0` when the entry thread returns `DllMain`'s `TRUE`.

## Build

```
cargo build --release
```

## How it works

1. PE32+ headers and sections are copied into a flat image of `SizeOfImage` bytes.
2. Memory is allocated in the target (`VirtualAllocEx`) and DIR64 base
   relocations are applied for the remote base.
3. Imports are resolved locally and rebased onto the target's module bases
   (system DLLs share base addresses across processes).
4. `.pdata` is registered with the target's `RtlAddFunctionTable` when present,
   so SEH works inside the mapped image.
5. A remote thread runs a stub that registers the exception table and calls the
   entry point; the injector reports success when the thread exits with
   `DllMain`'s `TRUE`.

## Limitations

- x64 targets and x64 DLLs only.
- No TLS callbacks are invoked.
- Imports must come from DLLs already loaded in the target
  (`kernel32`, `ntdll`, `user32`, ...).
- The image is mapped RWX; per-section protections are not applied.
- A manual-mapped DLL never appears in the module list, so the
  "already injected" check only catches `LoadLibrary`'d copies.

## License

MIT
