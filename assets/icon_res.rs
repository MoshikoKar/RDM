// Shared by the build scripts of rdpmon-svc and rdpmon-config (`include!`).
// Converts assets/rdpmon.ico into a Win32 .res file (RT_ICON + RT_GROUP_ICON,
// group id 1 = the executable's icon in Explorer) and passes it to link.exe.
// Written by hand so that the build needs neither rc.exe nor extra crates.

fn embed_app_icon() {
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ico_path = manifest_dir.join("../../assets/rdpmon.ico");
    println!("cargo:rerun-if-changed={}", ico_path.display());
    let ico = std::fs::read(&ico_path).expect("assets/rdpmon.ico is missing (run scripts/make-icon.ps1)");
    let u16_at = |o: usize| u16::from_le_bytes([ico[o], ico[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes([ico[o], ico[o + 1], ico[o + 2], ico[o + 3]]);
    assert!(ico.len() > 6 && u16_at(2) == 1, "rdpmon.ico is not an icon file");
    let count = u16_at(4) as usize;

    fn resource(out: &mut Vec<u8>, kind: u16, id: u16, flags: u16, data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataSize
        out.extend_from_slice(&32u32.to_le_bytes()); // HeaderSize
        out.extend_from_slice(&[0xFF, 0xFF]);
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&[0xFF, 0xFF]);
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
        out.extend_from_slice(&flags.to_le_bytes()); // MemoryFlags
        out.extend_from_slice(&0x0409u16.to_le_bytes()); // LanguageId
        out.extend_from_slice(&0u32.to_le_bytes()); // Version
        out.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }

    let mut res = Vec::new();
    resource(&mut res, 0, 0, 0, &[]); // mandatory empty first entry
    let mut group = Vec::new();
    group.extend_from_slice(&[0, 0, 1, 0]);
    group.extend_from_slice(&(count as u16).to_le_bytes());
    for i in 0..count {
        let e = 6 + 16 * i;
        let (len, off) = (u32_at(e + 8) as usize, u32_at(e + 12) as usize);
        resource(&mut res, 3, (i + 1) as u16, 0x1010, &ico[off..off + len]); // RT_ICON
        group.extend_from_slice(&ico[e..e + 12]);
        group.extend_from_slice(&((i + 1) as u16).to_le_bytes());
    }
    resource(&mut res, 14, 1, 0x1030, &group); // RT_GROUP_ICON

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("rdpmon-icon.res");
    std::fs::write(&out, res).expect("cannot write icon resource");
    println!("cargo:rustc-link-arg-bins={}", out.display());
}
