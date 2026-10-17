//! A tiny scripted HTTP/1.1 server for unit tests (std only, one thread).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// What the server does for one request.
#[derive(Clone, Debug)]
pub enum Reply {
    /// Answer with a status, extra headers and a body.
    Json(u16, Vec<(&'static str, String)>, String),
    /// Close the connection without answering (a network error).
    Drop,
}

pub fn json(status: u16, body: &str) -> Reply {
    Reply::Json(status, vec![], body.to_string())
}

/// A request the server saw.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl Seen {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

pub struct FakeServer {
    pub url: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakeServer {
    /// Serves `replies` in order; once they run out, answers 500.
    /// A reply whose path filter is `Some(p)` only matches requests to `p`.
    pub fn start(replies: Vec<Reply>) -> FakeServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let replies = Arc::new(Mutex::new(
            replies
                .into_iter()
                .collect::<std::collections::VecDeque<_>>(),
        ));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let seen = seen2.clone();
                let replies = replies.clone();
                thread::spawn(move || handle(stream, seen, replies));
            }
        });
        FakeServer { url, seen }
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn handle(
    stream: TcpStream,
    seen: Arc<Mutex<Vec<Seen>>>,
    replies: Arc<Mutex<std::collections::VecDeque<Reply>>>,
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut headers = BTreeMap::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).unwrap();
    seen.lock().unwrap().push(Seen {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    let reply = replies.lock().unwrap().pop_front().unwrap_or_else(|| {
        json(
            500,
            r#"{"error":{"code":"internal","message":"no more replies"}}"#,
        )
    });
    let mut stream = stream;
    match reply {
        Reply::Drop => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        Reply::Json(status, extra, body) => {
            let mut resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (k, v) in extra {
                resp.push_str(&format!("{k}: {v}\r\n"));
            }
            resp.push_str("\r\n");
            resp.push_str(&body);
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    }
}

pub const ORG: &str = "11111111-2222-3333-4444-555555555555";

pub fn job_json(id: &str, status: &str) -> String {
    format!(
        r#"{{"id":"{id}","live":false,"source":"api","kind":"escpos","status":"{status}","status_detail":"","title":"t","reference":"","copies":1,"printer_id":null,"printer_name":null,"station_id":null,"station_name":null,"location_id":null,"location_name":null,"size":10,"attempts":0,"billed_as":"test","created_by":null,"reprint_of":null,"scheduled_for":null,"created_at":"2026-10-16T08:00:00.123456Z","sent_at":null,"printed_at":null,"finished_at":null,"future_field":42}}"#
    )
}
