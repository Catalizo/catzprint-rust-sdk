//! A minimal webhook receiver (std only) that verifies signatures.
//!
//! ```sh
//! CATZPRINT_WEBHOOK_SECRET=whsec_... cargo run --example verify_webhook
//! ```
//! It listens on http://127.0.0.1:4242. Run with `--self-test` to send it a
//! signed sample event from the same process.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use catzprint::webhooks;

fn handle(mut stream: TcpStream, secret: &str) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let (mut len, mut signature) = (0usize, String::new());
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h == "\r\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().unwrap_or(0),
                "catzprint-signature" => signature = v.trim().to_string(),
                _ => {}
            }
        }
    }
    let mut body = vec![0; len.min(1 << 20)];
    reader.read_exact(&mut body)?;
    // Verify the raw bytes exactly as received.
    let status = match webhooks::construct_event(&body, &signature, secret) {
        Ok(event) => {
            println!("verified {} for org {}", event.event_type, event.org_id);
            if let Some(job) = event.job() {
                println!("  job {} is {}", job.id, job.status);
            }
            "200 OK"
        }
        Err(e) => {
            eprintln!("rejected delivery: {e}");
            "400 Bad Request"
        }
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

fn main() -> std::io::Result<()> {
    let secret =
        std::env::var("CATZPRINT_WEBHOOK_SECRET").unwrap_or_else(|_| "whsec_example".into());
    let listener = TcpListener::bind("127.0.0.1:4242")?;
    println!("Listening on http://127.0.0.1:4242");
    if std::env::args().any(|a| a == "--self-test") {
        let body = r#"{"type":"job.printed","created_at":"2026-10-16T08:00:00Z","org_id":"org_1","data":{"job":{"id":"job_1","status":"printed"}}}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let sig = webhooks::sign(&secret, now, body);
        let mut client = TcpStream::connect("127.0.0.1:4242")?;
        write!(client, "POST / HTTP/1.1\r\nHost: localhost\r\nCatzPrint-Signature: {sig}\r\nContent-Length: {}\r\n\r\n{body}", body.len())?;
        let (stream, _) = listener.accept()?;
        handle(stream, &secret)?;
        let mut answer = String::new();
        client.read_to_string(&mut answer)?;
        println!("endpoint answered: {}", answer.lines().next().unwrap_or(""));
        return Ok(());
    }
    for stream in listener.incoming() {
        if let Err(e) = handle(stream?, &secret) {
            eprintln!("connection error: {e}");
        }
    }
    Ok(())
}
