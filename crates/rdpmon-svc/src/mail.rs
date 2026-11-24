//! SMTP delivery. TLS uses the Windows certificate store (SChannel via
//! native-tls), so enterprise CAs trusted by the computer are honored.

use crate::db::Message;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Address, SmtpTransport, Transport};
use rdpmon_core::config::{Encryption, SmtpConfig};
use std::time::Duration;

/// Sends `m`. `to_override` replaces the configured To list (weekly report).
/// Errors are human readable and never contain credentials.
pub fn send(smtp: &SmtpConfig, to_override: Option<&[String]>, m: &Message) -> Result<(), String> {
    send_classified(smtp, to_override, m).map_err(|e| e.message)
}

pub struct SendError {
    pub message: String,
    /// The server (or address parsing) rejected *this message*: retrying it
    /// cannot help and it must not hold up the rest of the queue.
    pub message_rejected: bool,
}

pub fn send_classified(smtp: &SmtpConfig, to_override: Option<&[String]>, m: &Message) -> Result<(), SendError> {
    let rejected = |message: String| SendError { message, message_rejected: true };
    let config_error = |message: String| SendError { message, message_rejected: false };
    let addr = |s: &str| -> Result<Address, SendError> {
        s.trim().parse::<Address>().map_err(|_| config_error(format!("'{s}' is not a valid email address.")))
    };
    let mut b = lettre::Message::builder()
        .from(Mailbox::new(Some("RDP Monitor".into()), addr(&smtp.from)?))
        .subject(m.subject.clone());
    let to = to_override.filter(|l| !l.is_empty()).unwrap_or(&smtp.to);
    if to.is_empty() {
        return Err(config_error("No recipients are configured.".into()));
    }
    for a in to {
        b = b.to(Mailbox::new(None, addr(a)?));
    }
    for a in &smtp.cc {
        b = b.cc(Mailbox::new(None, addr(a)?));
    }
    for a in &smtp.bcc {
        b = b.bcc(Mailbox::new(None, addr(a)?));
    }
    let msg = b
        .multipart(MultiPart::alternative_plain_html(m.text.clone(), m.html.clone()))
        .map_err(|e| rejected(format!("Could not build the email: {e}")))?;

    let host = smtp.host.trim();
    let tls = match smtp.encryption {
        Encryption::None => Tls::None,
        Encryption::Starttls | Encryption::Tls => {
            let p = TlsParameters::new(host.to_string())
                .map_err(|e| SendError { message: format!("TLS setup failed: {e}"), message_rejected: false })?;
            if smtp.encryption == Encryption::Tls { Tls::Wrapper(p) } else { Tls::Required(p) }
        }
    };
    let mut t = SmtpTransport::builder_dangerous(host)
        .port(smtp.port)
        .tls(tls)
        .timeout(Some(Duration::from_secs(smtp.timeout_seconds.max(5) as u64)));
    if !smtp.username.trim().is_empty() {
        t = t
            .credentials(Credentials::new(smtp.username.trim().to_string(), smtp.password.clone()))
            .authentication(vec![Mechanism::Plain, Mechanism::Login]);
    }
    t.build().send(&msg).map(|_| ()).map_err(|e| {
        let code = e.status().map(|c| c.to_string()).unwrap_or_default();
        // 550-554: mailbox/recipient/content refused for this message.
        // (535/530 authentication errors affect every message: keep retrying.)
        let message_rejected = ["550", "551", "552", "553", "554"].iter().any(|c| code.starts_with(c));
        SendError { message: describe(&e, host, smtp.port, smtp.encryption), message_rejected }
    })
}

fn describe(e: &lettre::transport::smtp::Error, host: &str, port: u16, enc: Encryption) -> String {
    let code = e.status().map(|c| c.to_string()).unwrap_or_default();
    let detail = e.to_string();
    if e.is_timeout() {
        format!("Timed out talking to SMTP server {host}:{port}. Check the host name, port and firewall.")
    } else if e.is_tls() {
        format!(
            "Secure connection to {host}:{port} failed ({detail}). Check the encryption mode ({}) and that the server certificate is valid and trusted.",
            match enc { Encryption::Tls => "implicit TLS", Encryption::Starttls => "STARTTLS", Encryption::None => "none" }
        )
    } else if code.starts_with("535") || code.starts_with("534") || code.starts_with("530") {
        format!("SMTP authentication failed ({code}): the server rejected the user name or password, or requires a different authentication method.")
    } else if code.starts_with("55") || code.starts_with("553") {
        format!("The SMTP server refused the sender or a recipient ({detail}).")
    } else if e.is_permanent() {
        format!("The SMTP server rejected the message ({detail}).")
    } else if e.is_transient() {
        format!("The SMTP server is temporarily unavailable ({detail}). Delivery will be retried.")
    } else {
        format!("Could not deliver via SMTP server {host}:{port}: {detail}")
    }
}

#[cfg(test)]
pub mod fake {
    //! Minimal scripted SMTP server for tests (plain TCP only).
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    pub struct Fake {
        pub port: u16,
        pub transcript: mpsc::Receiver<String>,
    }

    /// `auth_ok`: response to AUTH. `rcpt_reply`: response to RCPT TO.
    pub fn start(auth_reply: &'static str, rcpt_reply: &'static str) -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let Ok((s, _)) = l.accept() else { return };
            let mut w = s.try_clone().unwrap();
            let mut r = BufReader::new(s);
            let mut all = String::new();
            let _ = w.write_all(b"220 fake ESMTP\r\n");
            let mut in_data = false;
            let mut line = String::new();
            while r.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                all.push_str(&line);
                let cmd = line.trim_end().to_ascii_uppercase();
                let reply: &str = if in_data {
                    if cmd == "." { in_data = false; "250 queued\r\n" } else { "" }
                } else if cmd.starts_with("EHLO") {
                    "250-fake\r\n250 AUTH PLAIN LOGIN\r\n"
                } else if cmd.starts_with("AUTH") {
                    auth_reply
                } else if cmd.starts_with("MAIL") {
                    "250 ok\r\n"
                } else if cmd.starts_with("RCPT") {
                    rcpt_reply
                } else if cmd == "DATA" {
                    in_data = true;
                    "354 go\r\n"
                } else if cmd == "QUIT" {
                    let _ = w.write_all(b"221 bye\r\n");
                    break;
                } else {
                    "250 ok\r\n"
                };
                if !reply.is_empty() {
                    let _ = w.write_all(reply.as_bytes());
                }
                line.clear();
            }
            let _ = tx.send(all);
        });
        Fake { port, transcript: rx }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(port: u16) -> SmtpConfig {
        SmtpConfig {
            host: "127.0.0.1".into(),
            port,
            from: "rdp@example.com".into(),
            to: vec!["it@example.com".into()],
            timeout_seconds: 5,
            ..Default::default()
        }
    }

    fn msg() -> Message {
        Message { subject: "RDP ALERT test".into(), text: "plain body".into(), html: "<b>html body</b>".into() }
    }

    #[test]
    fn delivers_multipart_message() {
        let f = fake::start("235 ok\r\n", "250 ok\r\n");
        send(&cfg(f.port), None, &msg()).unwrap();
        let t = f.transcript.recv().unwrap();
        assert!(t.contains("RCPT TO:<it@example.com>"));
        assert!(t.contains("Subject: RDP ALERT test"));
        assert!(t.contains("multipart/alternative"));
    }

    #[test]
    fn reports_connection_failure() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = send(&cfg(port), None, &msg()).unwrap_err();
        assert!(e.contains("127.0.0.1") && e.contains(&port.to_string()), "{e}");
    }

    #[test]
    fn reports_authentication_failure_without_leaking_password() {
        let f = fake::start("535 5.7.8 bad credentials\r\n", "250 ok\r\n");
        let mut c = cfg(f.port);
        c.username = "svc-rdp".into();
        c.password = "S3cret-Value".into();
        let e = send(&c, None, &msg()).unwrap_err();
        assert!(e.contains("authentication failed"), "{e}");
        assert!(!e.contains("S3cret-Value"));
    }

    #[test]
    fn reports_rejected_recipient() {
        let f = fake::start("235 ok\r\n", "550 5.1.1 no such user\r\n");
        let e = send_classified(&cfg(f.port), None, &msg()).unwrap_err();
        assert!(e.message.contains("refused") || e.message.contains("rejected"), "{}", e.message);
        assert!(e.message_rejected, "550 must not block the rest of the queue");
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(!send_classified(&cfg(port), None, &msg()).unwrap_err().message_rejected, "outage is retried");
    }
}
