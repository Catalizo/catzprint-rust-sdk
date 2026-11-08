//! A minimal mDNS / DNS-SD browser for `_catzprint._tcp.local.` (SPEC §4.8),
//! written against the DNS wire format with tokio's UdpSocket: no extra crate.
//!
//! mDNS is unauthenticated: what is found here is only used to map a station
//! ID to its current address for stations the SDK already trusts (see
//! `LocalState::accepted_mdns`).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::transport::normalize_fingerprint;

/// The DNS-SD service type stations advertise.
pub(crate) const SERVICE: &str = "_catzprint._tcp.local.";

/// The IPv4 mDNS group.
pub(crate) const GROUP: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;
/// The QU ("unicast response") bit of a question's class.
const QU: u16 = 0x8000;

/// One station as announced over mDNS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MdnsStation {
    pub instance: String,
    pub station_id: String,
    pub org_id: String,
    pub location_id: String,
    pub port: u16,
    pub fingerprint: String,
    pub tls_mode: String,
    /// TXT `host`: parsed, never used to build a target.
    pub hostname: String,
    pub addresses: Vec<String>,
}

/// A PTR query for the CatzPrint service with the QU bit set.
pub(crate) fn build_query() -> Vec<u8> {
    let mut q = vec![0u8; 12];
    q[5] = 1; // QDCOUNT = 1
    for label in SERVICE.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&TYPE_PTR.to_be_bytes());
    q.extend_from_slice(&(CLASS_IN | QU).to_be_bytes());
    q
}

/// Reads a (possibly compressed) name at `pos`; returns it lower-cased-as-sent
/// with a trailing dot, and the position after it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    if out.is_empty() {
                        out.push('.');
                    }
                    return Some((out, end.unwrap_or(pos + 1)));
                }
                let label = msg.get(pos + 1..pos + 1 + len)?;
                out.push_str(&String::from_utf8_lossy(label));
                out.push('.');
                if out.len() > 255 {
                    return None;
                }
                pos += 1 + len;
            }
            0xC0 => {
                let off = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > 32 || off >= msg.len() {
                    return None;
                }
                pos = off;
            }
            _ => return None,
        }
    }
}

fn u16_at(msg: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]))
}

fn is_service_instance(n: &str) -> bool {
    n.len() > SERVICE.len() + 1 && n.ends_with(&format!(".{SERVICE}"))
}

/// Accumulates records from any number of responses.
#[derive(Debug, Default)]
pub(crate) struct Collector {
    ptr: HashSet<String>,
    srv: HashMap<String, (u16, String)>,
    txt: HashMap<String, HashMap<String, String>>,
    addr: HashMap<String, Vec<String>>,
    src: HashMap<String, String>,
    name: HashMap<String, String>,
}

impl Collector {
    /// Parses one response packet. Malformed packets and unrelated records
    /// are ignored.
    pub(crate) fn add(&mut self, msg: &[u8], from: IpAddr) {
        // Records are applied only when the whole section parses, like the
        // Go SDK's dnsmessage-based parser.
        let Some(recs) = parse_response(msg) else {
            return;
        };
        let src = match from {
            IpAddr::V4(v4) => Some(v4.to_string()),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v| v.to_string()),
        };
        for r in recs {
            let name = r.name.to_ascii_lowercase();
            match r.data {
                Rdata::Ptr(inst) => {
                    let lower = inst.to_ascii_lowercase();
                    if name == SERVICE && is_service_instance(&lower) {
                        self.ptr.insert(lower.clone());
                        self.name.insert(lower, inst);
                    }
                }
                Rdata::Srv(port, target) => {
                    if is_service_instance(&name) {
                        self.srv.insert(name.clone(), (port, target));
                        self.name.insert(name.clone(), r.name.clone());
                        if let Some(s) = &src {
                            self.src.insert(name, s.clone());
                        }
                    }
                }
                Rdata::Txt(strings) => {
                    if is_service_instance(&name) {
                        let mut kv = HashMap::new();
                        for s in strings {
                            let (k, v) = s.split_once('=').unwrap_or((s.as_str(), ""));
                            let k = k.trim().to_ascii_lowercase();
                            if !k.is_empty() {
                                // RFC 6763: the first one wins.
                                kv.entry(k).or_insert_with(|| v.to_string());
                            }
                        }
                        self.txt.insert(name.clone(), kv);
                        self.name.insert(name.clone(), r.name.clone());
                        if let Some(s) = &src {
                            self.src.insert(name, s.clone());
                        }
                    }
                }
                Rdata::A(ip) => {
                    let ip = ip.to_string();
                    let list = self.addr.entry(name).or_default();
                    if !list.contains(&ip) {
                        list.push(ip);
                    }
                }
            }
        }
    }

    /// Every complete, valid station seen so far, sorted by instance name.
    pub(crate) fn stations(&self) -> Vec<MdnsStation> {
        let mut names: Vec<&String> = self
            .txt
            .keys()
            .filter(|n| self.srv.contains_key(*n))
            .collect();
        names.sort();
        let mut out = Vec::new();
        for n in names {
            let kv = &self.txt[n];
            let (srv_port, target) = &self.srv[n];
            let get = |k: &str| kv.get(k).map(String::as_str).unwrap_or("");
            if get("v") != "1" || get("id").is_empty() {
                continue;
            }
            let port = match get("port").parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => *srv_port,
            };
            if port == 0 {
                continue;
            }
            let fp = normalize_fingerprint(get("fp"));
            if !get("fp").is_empty() && fp.is_empty() {
                continue; // malformed fingerprint: ignore the whole announcement
            }
            let as_sent = self.name.get(n).cloned().unwrap_or_else(|| n.clone());
            let instance = if as_sent
                .to_ascii_lowercase()
                .ends_with(&format!(".{SERVICE}"))
            {
                as_sent[..as_sent.len() - SERVICE.len() - 1].to_string()
            } else {
                as_sent
            };
            let mut st = MdnsStation {
                instance,
                station_id: get("id").to_string(),
                org_id: get("org").to_string(),
                location_id: get("loc").to_string(),
                port,
                fingerprint: fp,
                tls_mode: get("tls").to_string(),
                hostname: get("host").trim_end_matches('.').to_ascii_lowercase(),
                addresses: Vec::new(),
            };
            if let Some(ips) = self.addr.get(&target.to_ascii_lowercase()) {
                for ip in ips {
                    if !st.addresses.contains(ip) {
                        st.addresses.push(ip.clone());
                    }
                }
            }
            if st.addresses.is_empty() {
                if let Some(s) = self.src.get(n) {
                    st.addresses.push(s.clone());
                }
            }
            out.push(st);
        }
        out
    }
}

enum Rdata {
    Ptr(String),
    Srv(u16, String),
    Txt(Vec<String>),
    A(Ipv4Addr),
}

struct Record {
    name: String,
    data: Rdata,
}

/// Parses a response's answer and additional records (authority records are
/// skipped). `None` for anything malformed or not a response.
fn parse_response(msg: &[u8]) -> Option<Vec<Record>> {
    if msg.len() < 12 {
        return None;
    }
    let flags = u16_at(msg, 2)?;
    if flags & 0x8000 == 0 {
        return None; // a query
    }
    let qd = u16_at(msg, 4)? as usize;
    let an = u16_at(msg, 6)? as usize;
    let ns = u16_at(msg, 8)? as usize;
    let ar = u16_at(msg, 10)? as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, p) = read_name(msg, pos)?;
        pos = p + 4;
    }
    let mut out = Vec::new();
    for i in 0..an + ns + ar {
        let (name, p) = read_name(msg, pos)?;
        let typ = u16_at(msg, p)?;
        let rdlen = u16_at(msg, p + 8)? as usize;
        let start = p + 10;
        let rdata = msg.get(start..start + rdlen)?;
        pos = start + rdlen;
        if i >= an && i < an + ns {
            continue; // authority
        }
        let data = match typ {
            TYPE_PTR => Rdata::Ptr(read_name(msg, start)?.0),
            TYPE_SRV => {
                if rdlen < 7 {
                    return None;
                }
                let port = u16_at(msg, start + 4)?;
                Rdata::Srv(port, read_name(msg, start + 6)?.0)
            }
            TYPE_TXT => {
                let mut strings = Vec::new();
                let mut i = 0;
                while i < rdata.len() {
                    let l = rdata[i] as usize;
                    let s = rdata.get(i + 1..i + 1 + l)?;
                    strings.push(String::from_utf8_lossy(s).into_owned());
                    i += 1 + l;
                }
                Rdata::Txt(strings)
            }
            TYPE_A => {
                if rdlen != 4 {
                    return None;
                }
                Rdata::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
            }
            _ => continue,
        };
        out.push(Record { name, data });
    }
    Some(out)
}

/// Sends a query to `dst` (the mDNS group, or a unicast address in tests) and
/// collects answers until `timeout`. The query comes from an ephemeral port,
/// so responders answer unicast to it (QU bit / RFC 6762 §6.7 legacy
/// unicast). Dropping the future ends the browse and closes the socket.
pub(crate) async fn browse(timeout: Duration, dst: SocketAddr) -> io::Result<Vec<MdnsStation>> {
    let query = build_query();
    let bind: SocketAddr = if dst.ip().is_loopback() {
        (Ipv4Addr::LOCALHOST, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    if dst.ip().is_multicast() {
        let _ = sock.set_multicast_ttl_v4(255);
    }
    let start = Instant::now();
    let deadline = start + timeout;
    // One resend shortly after the first query: UDP may drop packets.
    let resend_at = start + (timeout / 3).min(Duration::from_millis(300));
    sock.send_to(&query, dst).await?;
    let mut resent = false;
    let mut col = Collector::default();
    let mut buf = vec![0u8; 9000];
    loop {
        let until = if resent {
            deadline
        } else {
            resend_at.min(deadline)
        };
        match tokio::time::timeout_at(until, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => col.add(&buf[..n], from.ip()),
            Ok(Err(_)) => {
                // ICMP port unreachable and the like: keep listening.
                if Instant::now() >= deadline {
                    break;
                }
            }
            Err(_) if !resent && Instant::now() < deadline => {
                resent = true;
                let _ = sock.send_to(&query, dst).await;
            }
            Err(_) => break,
        }
    }
    Ok(col.stations())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Encodes a name without compression.
    fn name(n: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for l in n.trim_end_matches('.').split('.') {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    fn rr(n: &str, typ: u16, rdata: Vec<u8>) -> Vec<u8> {
        let mut out = name(n);
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(CLASS_IN | 0x8000).to_be_bytes());
        out.extend_from_slice(&120u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend(rdata);
        out
    }

    /// A response with answers and additionals (no compression).
    pub(crate) fn response(answers: Vec<Vec<u8>>, additionals: Vec<Vec<u8>>) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[2] = 0x84; // QR + AA
        m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        m[10..12].copy_from_slice(&(additionals.len() as u16).to_be_bytes());
        for r in answers.into_iter().chain(additionals) {
            m.extend(r);
        }
        m
    }

    pub(crate) fn ptr(inst: &str) -> Vec<u8> {
        rr(SERVICE, TYPE_PTR, name(inst))
    }
    pub(crate) fn srv(inst: &str, port: u16, target: &str) -> Vec<u8> {
        let mut d = vec![0, 0, 0, 0];
        d.extend_from_slice(&port.to_be_bytes());
        d.extend(name(target));
        rr(inst, TYPE_SRV, d)
    }
    pub(crate) fn txt(inst: &str, kv: &[&str]) -> Vec<u8> {
        let mut d = Vec::new();
        for s in kv {
            d.push(s.len() as u8);
            d.extend_from_slice(s.as_bytes());
        }
        rr(inst, TYPE_TXT, d)
    }
    pub(crate) fn a(host: &str, ip: Ipv4Addr) -> Vec<u8> {
        rr(host, TYPE_A, ip.octets().to_vec())
    }

    /// A complete station announcement as §4.8 describes it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn answer(
        inst_name: &str,
        id: &str,
        org: &str,
        loc: &str,
        port: u16,
        fp: &str,
        ip: Ipv4Addr,
        extra: &[&str],
    ) -> Vec<u8> {
        let inst = format!("{inst_name} (CatzPrint).{SERVICE}");
        let host = format!("catzprint-{id}.local.");
        let mut kv: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
        kv.extend([
            "v=1".into(),
            format!("id={id}"),
            format!("org={org}"),
            format!("loc={loc}"),
            format!("port={port}"),
            format!("fp={fp}"),
            "tls=self_signed".into(),
            "host=".into(),
        ]);
        let kv: Vec<&str> = kv.iter().map(String::as_str).collect();
        response(
            vec![ptr(&inst)],
            vec![srv(&inst, port, &host), txt(&inst, &kv), a(&host, ip)],
        )
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn query_has_one_qu_ptr_question() {
        let q = build_query();
        assert_eq!(&q[4..6], &[0, 1]);
        assert_eq!(q[2] & 0x80, 0, "not a response");
        let (n, p) = read_name(&q, 12).unwrap();
        assert_eq!(n, SERVICE);
        assert_eq!(u16_at(&q, p).unwrap(), TYPE_PTR);
        assert_eq!(u16_at(&q, p + 2).unwrap(), CLASS_IN | QU);
    }

    #[test]
    fn parses_an_announcement() {
        let fp = "a1".repeat(32);
        let mut col = Collector::default();
        col.add(
            &answer(
                "Kitchen PC",
                "st1",
                "org1",
                "loc1",
                7443,
                &fp,
                Ipv4Addr::new(192, 168, 1, 20),
                &[],
            ),
            ip("192.168.1.20"),
        );
        let got = col.stations();
        assert_eq!(got.len(), 1);
        let s = &got[0];
        assert_eq!(s.instance, "Kitchen PC (CatzPrint)");
        assert_eq!(
            (
                s.station_id.as_str(),
                s.org_id.as_str(),
                s.location_id.as_str()
            ),
            ("st1", "org1", "loc1")
        );
        assert_eq!(s.port, 7443);
        assert_eq!(s.fingerprint, fp);
        assert_eq!(s.addresses, vec!["192.168.1.20"]);
        assert_eq!(s.hostname, "");
    }

    #[test]
    fn compressed_names_are_followed() {
        // PTR whose target points back at the question-less answer name.
        let inst = format!("Bar (CatzPrint).{SERVICE}");
        let mut m = response(vec![ptr(&inst)], vec![]);
        // Append a TXT record whose owner name is a pointer to the PTR's
        // rdata (the instance name, at offset 12 + name(SERVICE) + 10).
        let target_off = 12 + name(SERVICE).len() + 10;
        m[11] = 2; // ARCOUNT = 2
        let mut t = vec![0xC0 | (target_off >> 8) as u8, target_off as u8];
        t.extend_from_slice(&TYPE_TXT.to_be_bytes());
        t.extend_from_slice(&CLASS_IN.to_be_bytes());
        t.extend_from_slice(&120u32.to_be_bytes());
        let kv = ["v=1", "id=st2", "port=7443"];
        let mut d = Vec::new();
        for s in kv {
            d.push(s.len() as u8);
            d.extend_from_slice(s.as_bytes());
        }
        t.extend_from_slice(&(d.len() as u16).to_be_bytes());
        t.extend(d);
        m.extend(t);
        let mut s = vec![0xC0 | (target_off >> 8) as u8, target_off as u8];
        s.extend_from_slice(&TYPE_SRV.to_be_bytes());
        s.extend_from_slice(&CLASS_IN.to_be_bytes());
        s.extend_from_slice(&120u32.to_be_bytes());
        let tgt = name("bar.local.");
        s.extend_from_slice(&((6 + tgt.len()) as u16).to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 0, 0x1d, 0x13]);
        s.extend(tgt);
        m.extend(s);
        let mut col = Collector::default();
        col.add(&m, ip("10.0.0.9"));
        let got = col.stations();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].station_id, "st2");
        assert_eq!(
            got[0].addresses,
            vec!["10.0.0.9"],
            "source address fallback"
        );
    }

    #[test]
    fn split_packets_and_source_fallback() {
        let fp = "0f".repeat(32);
        let inst = format!("Bar (CatzPrint).{SERVICE}");
        let mut col = Collector::default();
        col.add(&response(vec![ptr(&inst)], vec![]), ip("10.0.0.9"));
        assert!(
            col.stations().is_empty(),
            "incomplete announcement accepted"
        );
        let fp_kv = format!("FP={}", fp.to_uppercase());
        col.add(
            &response(
                vec![
                    srv(&inst, 7000, "catzprint-st2.local."),
                    txt(
                        &inst,
                        &[
                            "v=1",
                            "id=st2",
                            "org=org1",
                            "loc=loc1",
                            "port=7443",
                            &fp_kv,
                            "tls=public",
                            "host=10-0-0-9.abcdefghij.local.catzprint.com",
                        ],
                    ),
                ],
                vec![],
            ),
            ip("10.0.0.9"),
        );
        let got = col.stations();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].port, 7443);
        assert_eq!(got[0].fingerprint, fp);
        assert_eq!(got[0].addresses, vec!["10.0.0.9"]);
        assert_eq!(got[0].hostname, "10-0-0-9.abcdefghij.local.catzprint.com");
    }

    #[test]
    fn rejects_bad_announcements() {
        let fp = "aa".repeat(32);
        let lan = Ipv4Addr::new(192, 168, 1, 2);
        let full = answer("D", "st1", "o", "l", 7443, &fp, lan, &[]);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "wrong version",
                answer("A", "st1", "o", "l", 7443, &fp, lan, &["v=2"]),
            ),
            (
                "bad fingerprint",
                answer("B", "st1", "o", "l", 7443, "zz", lan, &[]),
            ),
            ("missing id", answer("C", "", "o", "l", 7443, &fp, lan, &[])),
            ("truncated", full[..40].to_vec()),
            ("not a response", build_query()),
        ];
        for (what, msg) in cases {
            let mut col = Collector::default();
            col.add(&msg, ip("192.168.1.2"));
            assert!(col.stations().is_empty(), "{what}: accepted");
        }
        let other = response(
            vec![
                rr("_http._tcp.local.", TYPE_PTR, name("x._http._tcp.local.")),
                txt("x._http._tcp.local.", &["v=1", "id=evil"]),
                srv("x._http._tcp.local.", 80, "x.local."),
            ],
            vec![],
        );
        let mut col = Collector::default();
        col.add(&other, ip("192.168.1.3"));
        assert!(col.stations().is_empty(), "foreign service accepted");
        // A pointer loop is rejected, not followed forever.
        let mut looped = response(vec![], vec![]);
        looped[7] = 1;
        looped.extend_from_slice(&[0xC0, 12]);
        let mut col = Collector::default();
        col.add(&looped, ip("192.168.1.3"));
        assert!(col.stations().is_empty());
    }
}
