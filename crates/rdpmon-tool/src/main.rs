//! Offline administration tool: key generation, configuration-package and
//! release signing, password hashing. Run it on an administrator workstation;
//! keep private keys off the managed endpoints.

use rdpmon_core::crypto::{b64, decode_signing_key, generate_signing_key, hex};
use rdpmon_core::{package, password, release};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};

const USAGE: &str = "rdpmon-tool - RDP Monitor signing and key tool (administrator workstation only)

  rdpmon-tool keygen <name>
        Creates <name>.key (PRIVATE - keep offline) and <name>.pub.
  rdpmon-tool hash-password
        Prompts for a password and prints an Argon2id hash for
        [security] admin_password_hash in a configuration package.
  rdpmon-tool sign-config --key <file.key> --in <payload.toml> --out <file.rdpcfg>
        Signs a configuration payload. The payload must have [package] serial.
  rdpmon-tool verify-config --pub <file.pub> --in <file.rdpcfg>
  rdpmon-tool sign-release --key <file.key> --file <RDPMonitor-X.Y.Z-x64.msi> --version <X.Y.Z>
        Writes <file>.sig next to the MSI.
  rdpmon-tool verify-release --pub <file.pub> --file <msi> --version <X.Y.Z>";

fn arg(args: &[String], name: &str) -> Result<String, String> {
    let i = args.iter().position(|a| a == name).ok_or_else(|| format!("missing {name}"))?;
    args.get(i + 1).cloned().ok_or_else(|| format!("missing value for {name}"))
}

fn read_text(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn sha256_file(path: &str) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn file_name(path: &str) -> String {
    std::path::Path::new(path).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Reads a line from the console without echo.
fn read_secret(prompt: &str) -> String {
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE};
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0u32;
    let have_console = unsafe { GetConsoleMode(h, &mut mode) } != 0;
    if have_console {
        unsafe { SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) };
    }
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    if have_console {
        unsafe { SetConsoleMode(h, mode) };
        eprintln!();
    }
    s.trim_end_matches(['\r', '\n']).to_string()
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let name = args.get(1).ok_or("usage: rdpmon-tool keygen <name>")?;
            let (kf, pf) = (format!("{name}.key"), format!("{name}.pub"));
            if std::path::Path::new(&kf).exists() {
                return Err(format!("{kf} already exists; refusing to overwrite a key"));
            }
            let k = generate_signing_key();
            std::fs::write(&kf, b64(&k.to_bytes()) + "\n").map_err(|e| e.to_string())?;
            let public = b64(k.verifying_key().as_bytes());
            std::fs::write(&pf, public.clone() + "\n").map_err(|e| e.to_string())?;
            println!("Private key: {kf}  (store offline; anyone holding it can sign packages)");
            println!("Public key:  {pf}");
            println!("{public}");
            Ok(())
        }
        Some("hash-password") => {
            let p1 = read_secret("New administration password: ");
            password::check_strength(&p1)?;
            if read_secret("Confirm password: ") != p1 {
                return Err("passwords do not match".into());
            }
            println!("{}", password::hash(&p1)?);
            Ok(())
        }
        Some("sign-config") => {
            let key = decode_signing_key(read_text(&arg(args, "--key")?)?.trim())?;
            let payload = read_text(&arg(args, "--in")?)?;
            let out = arg(args, "--out")?;
            let signed = package::sign(&payload, &key)?;
            std::fs::write(&out, signed).map_err(|e| e.to_string())?;
            println!("Signed configuration package written to {out}");
            Ok(())
        }
        Some("verify-config") => {
            let public = read_text(&arg(args, "--pub")?)?;
            let data = std::fs::read(arg(args, "--in")?).map_err(|e| e.to_string())?;
            let p = package::verify(&data, public.trim())?;
            println!("Valid package: serial {} '{}'", p.serial, p.description);
            Ok(())
        }
        Some("sign-release") => {
            let key = decode_signing_key(read_text(&arg(args, "--key")?)?.trim())?;
            let file = arg(args, "--file")?;
            let version = arg(args, "--version")?;
            let name = file_name(&file);
            if name != format!("RDPMonitor-{version}-x64.msi") {
                return Err(format!("file must be named RDPMonitor-{version}-x64.msi (got {name})"));
            }
            let sig = release::sign(&name, &version, &sha256_file(&file)?, &key);
            let out = format!("{file}.sig");
            std::fs::write(&out, serde_json::to_string_pretty(&sig).expect("serializable")).map_err(|e| e.to_string())?;
            println!("Release signature written to {out}");
            Ok(())
        }
        Some("verify-release") => {
            let public = read_text(&arg(args, "--pub")?)?;
            let file = arg(args, "--file")?;
            let version = arg(args, "--version")?;
            let sig: release::SigFile = serde_json::from_str(&read_text(&format!("{file}.sig"))?).map_err(|e| e.to_string())?;
            release::verify(&sig, &file_name(&file), &version, &sha256_file(&file)?, public.trim())?;
            println!("Valid release signature for {} {version}", file_name(&file));
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
