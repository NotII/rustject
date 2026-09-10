use crate::pe;
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

const ACCESS: u32 =
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD;

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateThreadEx(
        thread: *mut HANDLE,
        access: u32,
        obj_attrs: *mut c_void,
        process: HANDLE,
        start_routine: *mut c_void,
        argument: *mut c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wstr(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

// toolhelp lists zombie processes too; skip any that already exited
fn alive(pid: u32) -> bool {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        ok != 0 && code == 259 // STILL_ACTIVE
    }
}

pub fn pid_named(exe: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                if wstr(&e.szExeFile).eq_ignore_ascii_case(exe) && alive(e.th32ProcessID) {
                    found = Some(e.th32ProcessID);
                    break;
                }
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
}

pub fn modules(pid: u32) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: MODULEENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snap, &mut e) != 0 {
            loop {
                out.insert(wstr(&e.szModule).to_lowercase(), e.modBaseAddr as u64);
                if Module32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

pub fn open(pid: u32) -> Option<HANDLE> {
    let h = unsafe { OpenProcess(ACCESS, 0, pid) };
    if h.is_null() { None } else { Some(h) }
}

pub fn close(h: HANDLE) {
    unsafe { CloseHandle(h) };
}

// System DLLs share base addresses across processes, so a local export
// address rebased onto the target's module base is valid remotely.
fn remote_fn(local_fn: usize, mods: &HashMap<String, u64>) -> Option<u64> {
    if local_fn == 0 {
        return None;
    }
    unsafe {
        let mut h: HMODULE = null_mut();
        if GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            local_fn as *const u16,
            &mut h,
        ) == 0
        {
            return None;
        }
        let mut buf = [0u16; 260];
        let n = GetModuleFileNameW(h, buf.as_mut_ptr(), 260) as usize;
        if n == 0 {
            return None;
        }
        let path = wstr(&buf[..n]);
        let base = path.rsplit(['\\', '/']).next()?.to_lowercase();
        let remote_base = *mods.get(&base)?;
        Some(remote_base + (local_fn as u64 - h as u64))
    }
}

pub fn resolver<'a>(mods: &'a HashMap<String, u64>) -> impl Fn(&str, &str) -> Option<u64> + 'a {
    move |dll: &str, name: &str| {
        unsafe {
            let w = wide(dll);
            let mut h = GetModuleHandleW(w.as_ptr());
            if h.is_null() {
                h = LoadLibraryW(w.as_ptr());
            }
            if h.is_null() {
                return None;
            }
            let mut cname = name.as_bytes().to_vec();
            cname.push(0);
            let f = GetProcAddress(h, cname.as_ptr())?;
            remote_fn(f as usize, mods)
        }
    }
}

// Remote stub contract: rcx = image base (thread param); registers .pdata
// for SEH when present, then calls DllMain(base, DLL_PROCESS_ATTACH, null).
fn dllmain_stub(ep_rva: u32, rtl: u64, exc_rva: u32, exc_n: u32) -> Vec<u8> {
    let ep = (ep_rva as i32).to_le_bytes();
    if rtl == 0 || exc_n == 0 {
        let mut s = vec![0x48, 0x83, 0xEC, 0x28, 0xBA, 0x01, 0, 0, 0, 0x4D, 0x31, 0xC0, 0x48, 0x8D, 0x81];
        s.extend_from_slice(&ep);
        s.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3]);
        return s;
    }
    let mut s = vec![0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCB, 0x48, 0x8D, 0x8B];
    s.extend_from_slice(&(exc_rva as i32).to_le_bytes());
    s.push(0xBA);
    s.extend_from_slice(&exc_n.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x89, 0xD8, 0x48, 0xB8]);
    s.extend_from_slice(&rtl.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x89, 0xD9, 0xBA, 0x01, 0, 0, 0, 0x4D, 0x31, 0xC0, 0x48, 0x8D, 0x83]);
    s.extend_from_slice(&ep);
    s.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3]);
    s
}

fn remote_thread(handle: HANDLE, start: usize, arg: usize) -> Option<HANDLE> {
    unsafe {
        let routine: LPTHREAD_START_ROUTINE = std::mem::transmute(start as *const c_void);
        let thr = CreateRemoteThread(handle, null(), 0, routine, arg as *const c_void, 0, null_mut());
        if !thr.is_null() {
            return Some(thr);
        }
        let mut h: HANDLE = null_mut();
        let st = NtCreateThreadEx(
            &mut h,
            0x1FFFFF,
            null_mut(),
            handle,
            start as *mut c_void,
            arg as *mut c_void,
            0,
            0,
            0,
            0,
            null_mut(),
        );
        if st == 0 && !h.is_null() { Some(h) } else { None }
    }
}

pub fn manual_map(handle: HANDLE, pid: u32, path: &Path) -> Result<(), String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut img = pe::map(&raw)?;
    unsafe {
        let dest = VirtualAllocEx(handle, null(), img.size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if dest.is_null() {
            return Err(os_err("VirtualAllocEx image"));
        }
        let mods = modules(pid);
        pe::reloc(&mut img, dest as u64);
        let resolve = resolver(&mods);
        pe::imports(&mut img, &resolve)?;
        let mut wrote = 0usize;
        if WriteProcessMemory(handle, dest, img.data.as_ptr() as *const c_void, img.data.len(), &mut wrote) == 0 {
            return Err(os_err("WriteProcessMemory image"));
        }
        let (exc_rva, exc_n) = pe::exception_dir(&img);
        let rtl = resolve("ntdll.dll", "RtlAddFunctionTable").unwrap_or(0);
        let stub = dllmain_stub(img.entry_rva, rtl, exc_rva, exc_n);
        let stub_at = VirtualAllocEx(handle, null(), stub.len() + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if stub_at.is_null() {
            return Err(os_err("VirtualAllocEx stub"));
        }
        if WriteProcessMemory(handle, stub_at, stub.as_ptr() as *const c_void, stub.len(), &mut wrote) == 0 {
            return Err(os_err("WriteProcessMemory stub"));
        }
        FlushInstructionCache(handle, dest, img.size);
        FlushInstructionCache(handle, stub_at, stub.len());
        let thr = remote_thread(handle, stub_at as usize, dest as usize)
            .ok_or("remote thread creation failed")?;
        let wait = WaitForSingleObject(thr, 8000);
        let mut code = 0u32;
        GetExitCodeThread(thr, &mut code);
        CloseHandle(thr);
        if wait != WAIT_OBJECT_0 {
            return Err("entry thread did not finish".into());
        }
        if code != 1 {
            return Err(format!("DllMain returned {code}"));
        }
    }
    Ok(())
}
