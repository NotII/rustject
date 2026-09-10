mod inject;
mod pe;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

fn usage() -> ExitCode {
    println!("rustject — x64 manual-map DLL injector\n\nusage: rustject <dll> [-t|--target exe]\n\ndefault target: cs2.exe");
    ExitCode::SUCCESS
}

fn usage_err() -> ExitCode {
    eprintln!("usage: rustject <dll> [-t|--target exe]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut dll: Option<PathBuf> = None;
    let mut target = String::from("cs2.exe");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-t" | "--target" => match args.next() {
                Some(t) => target = t,
                None => return usage_err(),
            },
            "-h" | "--help" => return usage(),
            _ => dll = Some(PathBuf::from(a)),
        }
    }
    let Some(dll) = dll else { return usage_err() };
    if !dll.is_file() {
        eprintln!("[-] {} not found", dll.display());
        return ExitCode::FAILURE;
    }
    let name = dll.file_name().unwrap_or_default().to_string_lossy().into_owned();

    println!("[*] waiting for {target}... (Ctrl+C to quit)");
    let pid = loop {
        if let Some(p) = inject::pid_named(&target) {
            break p;
        }
        std::thread::sleep(Duration::from_secs(2));
    };
    println!("[*] {target} pid {pid}");

    if inject::modules(pid).contains_key(&name.to_lowercase()) {
        println!("[=] {name} already in module list, nothing to do");
        return ExitCode::SUCCESS;
    }

    // a freshly spawned target hasn't loaded every dll yet; wait until all
    // imports are resolvable remotely or manual mapping fails on missing ones
    let needed: Vec<String> = std::fs::read(&dll)
        .ok()
        .and_then(|raw| pe::map(&raw).ok())
        .map(|img| pe::import_dlls(&img))
        .unwrap_or_default();
    if !needed.is_empty() {
        let start = std::time::Instant::now();
        loop {
            let mods = inject::modules(pid);
            if needed.iter().all(|d| mods.contains_key(d)) {
                break;
            }
            if start.elapsed() > Duration::from_secs(60) {
                eprintln!("[!] timed out waiting for target modules, trying anyway");
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    let Some(handle) = inject::open(pid) else {
        eprintln!("[-] OpenProcess failed (try running as admin)");
        return ExitCode::FAILURE;
    };
    println!("[*] manual mapping {}", dll.display());
    let rc = match inject::manual_map(handle, pid, &dll) {
        Ok(()) => {
            println!("[+] {name} injected (manual map)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[-] {name}: {e}");
            ExitCode::FAILURE
        }
    };
    inject::close(handle);
    rc
}
