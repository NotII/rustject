pub struct Image {
    pub data: Vec<u8>,
    pub entry_rva: u32,
    pub image_base: u64,
    pub size: usize,
    opt: usize,
}

fn r16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn r32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn r64(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn cstr(d: &[u8], off: usize) -> String {
    if off >= d.len() {
        return String::new();
    }
    let s = &d[off..d.len().min(off + 256)];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

pub fn map(raw: &[u8]) -> Result<Image, String> {
    if raw.get(..2) != Some(b"MZ") {
        return Err("not an MZ executable".into());
    }
    let pe = r32(raw, 0x3C).ok_or("truncated")? as usize;
    if raw.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("not a PE".into());
    }
    if r16(raw, pe + 4) != Some(0x8664) {
        return Err("not x64".into());
    }
    let nsect = r16(raw, pe + 6).ok_or("truncated")? as usize;
    let soh = r16(raw, pe + 20).ok_or("truncated")? as usize;
    let opt = pe + 24;
    if r16(raw, opt) != Some(0x20B) {
        return Err("not PE32+".into());
    }
    let entry_rva = r32(raw, opt + 16).ok_or("truncated")?;
    let image_base = r64(raw, opt + 24).ok_or("truncated")?;
    let size = r32(raw, opt + 56).ok_or("truncated")? as usize;
    let soheaders = r32(raw, opt + 60).ok_or("truncated")? as usize;
    let mut data = vec![0u8; size];
    let n = soheaders.min(raw.len()).min(size);
    data[..n].copy_from_slice(&raw[..n]);
    let sect = opt + soh;
    for i in 0..nsect {
        let s = sect + i * 40;
        let (Some(vs), Some(va), Some(rs), Some(pr)) =
            (r32(raw, s + 8), r32(raw, s + 12), r32(raw, s + 16), r32(raw, s + 20))
        else {
            continue;
        };
        let n = (rs.min(if vs == 0 { rs } else { vs }) as usize).min(size.saturating_sub(va as usize));
        if pr != 0 && n > 0 {
            let avail = raw.len().saturating_sub(pr as usize);
            let n = n.min(avail);
            data[va as usize..va as usize + n].copy_from_slice(&raw[pr as usize..pr as usize + n]);
        }
    }
    Ok(Image { data, entry_rva, image_base, size, opt })
}

pub fn reloc(img: &mut Image, dest: u64) {
    let delta = dest.wrapping_sub(img.image_base);
    if delta == 0 {
        return;
    }
    let (Some(rva), Some(sz)) = (r32(&img.data, img.opt + 112 + 40), r32(&img.data, img.opt + 112 + 44)) else {
        return;
    };
    if rva == 0 || sz == 0 {
        return;
    }
    let mut pos = rva as usize;
    let end = (rva + sz) as usize;
    while pos + 8 <= end && pos + 8 <= img.data.len() {
        let va = r32(&img.data, pos).unwrap() as usize;
        let size = r32(&img.data, pos + 4).unwrap() as usize;
        if size < 8 {
            break;
        }
        let mut i = 8;
        while i + 2 <= size {
            let Some(ent) = r16(&img.data, pos + i) else { break };
            if ent >> 12 == 10 {
                let at = va + (ent & 0xFFF) as usize;
                if at + 8 <= img.data.len() {
                    let old = r64(&img.data, at).unwrap();
                    img.data[at..at + 8].copy_from_slice(&old.wrapping_add(delta).to_le_bytes());
                }
            }
            i += 2;
        }
        pos += size;
    }
}

pub fn imports(img: &mut Image, resolve: impl Fn(&str, &str) -> Option<u64>) -> Result<(), String> {
    let (Some(rva), Some(sz)) = (r32(&img.data, img.opt + 112 + 8), r32(&img.data, img.opt + 112 + 12)) else {
        return Ok(());
    };
    if rva == 0 {
        return Ok(());
    }
    let mut pos = rva as usize;
    let end = (rva + if sz == 0 { 20 * 64 } else { sz }) as usize;
    while pos + 20 <= end.min(img.data.len()) {
        let (Some(oft), Some(name_rva), Some(iat)) =
            (r32(&img.data, pos), r32(&img.data, pos + 12), r32(&img.data, pos + 16))
        else {
            break;
        };
        if name_rva == 0 {
            break;
        }
        let dll = cstr(&img.data, name_rva as usize);
        let mut thunk = (if oft != 0 { oft } else { iat }) as usize;
        let mut slot = iat as usize;
        while thunk + 8 <= img.data.len() && slot + 8 <= img.data.len() {
            let entry = r64(&img.data, thunk).unwrap();
            if entry == 0 {
                break;
            }
            if entry & (1 << 63) != 0 {
                return Err(format!("import {dll} by ordinal, unsupported"));
            }
            let name = cstr(&img.data, entry as usize + 2);
            let remote = resolve(&dll, &name).ok_or_else(|| format!("import {dll}!{name}"))?;
            img.data[slot..slot + 8].copy_from_slice(&remote.to_le_bytes());
            thunk += 8;
            slot += 8;
        }
        pos += 20;
    }
    Ok(())
}

pub fn exception_dir(img: &Image) -> (u32, u32) {
    let rva = r32(&img.data, img.opt + 112 + 24).unwrap_or(0);
    let sz = r32(&img.data, img.opt + 112 + 28).unwrap_or(0);
    (rva, sz / 12)
}
