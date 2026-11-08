//! Unit tests of the trust rules on internal types (the end-to-end tests
//! are in tests/local.rs).

use super::*;

fn client(cfg: LocalConfig) -> Client {
    Client::builder()
        .api_key("cz_test_abcdefghijklmnopqrstuvwxyz")
        .base_url("http://127.0.0.1:1")
        .org_id("org1")
        .local(cfg)
        .build()
        .unwrap()
}

fn listed(fp: &str) -> StoredToken {
    StoredToken {
        stations_updated_at: Some(Utc::now()),
        stations: vec![LocalEndpoint {
            station_id: "real-station".into(),
            local_enabled: true,
            tls_mode: "public".into(),
            port: 7443,
            cert_fingerprint_sha256: fp.into(),
            addresses: vec!["192.168.1.20".into()],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// H4 (the reviewer's TestRevMDNSHostnameImpostor): an mDNS impostor copying
/// a real station's ID and announcing its own public-cert hostname must not
/// produce a hostname target, nor its own fingerprint; with no cloud list an
/// announcement alone produces nothing.
#[tokio::test]
async fn mdns_hostname_impostor() {
    let (real_fp, evil_fp) = ("aa".repeat(32), "bb".repeat(32));
    let c = client(
        LocalConfig::new(LocalMode::Local)
            .discover(true)
            .all_locations(true),
    );
    let l = c.local_state().unwrap();
    let st = listed(&real_fp);
    let evil = MdnsStation {
        station_id: "real-station".into(),
        port: 7443,
        tls_mode: "public".into(),
        fingerprint: evil_fp.clone(),
        hostname: "192-168-1-66.attackerlbl.local.catzprint.com".into(),
        addresses: vec!["192.168.1.66".into()],
        ..Default::default()
    };
    let targets: Vec<Target> = l
        .accepted_mdns(std::slice::from_ref(&evil), Some(&st))
        .iter()
        .flat_map(mdns_targets)
        .collect();
    assert_eq!(targets.len(), 1, "{targets:?}");
    let t = &targets[0];
    assert_eq!(t.url, "https://192.168.1.66:7443");
    assert!(t.needs_pin());
    assert_eq!(t.fingerprint, real_fp, "pinned to the cloud's fingerprint");
    assert!(!t.url.contains("attackerlbl"));

    // No endpoint list (paired device): the announced fingerprint is not trusted.
    let alone = MdnsStation {
        station_id: "x".into(),
        port: 7443,
        tls_mode: "self_signed".into(),
        fingerprint: evil_fp.clone(),
        addresses: vec!["192.168.1.66".into()],
        ..Default::default()
    };
    assert!(l
        .accepted_mdns(std::slice::from_ref(&alone), None)
        .is_empty());
    // ...unless the user pinned that fingerprint.
    let pinned = client(
        LocalConfig::new(LocalMode::Local)
            .discover(true)
            .all_locations(true)
            .fingerprint("bar-pc", &evil_fp),
    );
    assert_eq!(
        pinned
            .local_state()
            .unwrap()
            .accepted_mdns(&[alone], None)
            .len(),
        1
    );

    // Public addresses announced over mDNS are dropped (M6).
    let mut public = evil.clone();
    public.addresses = vec!["203.0.113.9".into()];
    assert!(l.accepted_mdns(&[public], Some(&st)).is_empty());

    // A station the list says is turned off isn't used.
    let mut off = st.clone();
    off.stations[0].local_enabled = false;
    assert!(l
        .accepted_mdns(std::slice::from_ref(&evil), Some(&off))
        .is_empty());

    // Another organization's announcement is ignored.
    let mut other_org = evil;
    other_org.org_id = "org2".into();
    assert!(l.accepted_mdns(&[other_org], Some(&st)).is_empty());
}

/// M6/A10: IP URLs from the endpoint list must be private; hostnames are
/// only dialled directly under their own label and carry the SPKI pin.
#[test]
fn endpoint_targets_filter() {
    let fp = "cd".repeat(32);
    let spki = "ef".repeat(32);
    let ts = endpoint_targets(
        &LocalEndpoint {
            station_id: "s".into(),
            tls_mode: "public".into(),
            local_label: "abcdefghij".into(),
            cert_fingerprint_sha256: fp.clone(),
            public_spki_sha256: spki.clone(),
            urls: vec![
                "https://192-168-1-20.abcdefghij.local.catzprint.com:7443".into(),
                "https://192.168.1.20:7443".into(),
                "https://203.0.113.9:7443".into(),
                "https://[fd00::1]:7443".into(),
            ],
            ..Default::default()
        },
        "cloud",
    );
    assert_eq!(ts.len(), 3, "{ts:?}");
    assert_eq!(ts[0].label, "abcdefghij");
    assert_eq!(ts[0].spki, spki);
    assert!(!ts[0].needs_pin());
    assert_eq!(ts[1].fingerprint, fp);
    assert_eq!(ts[2].url, "https://[fd00::1]:7443");
    assert_eq!(ts[2].fingerprint, fp);
}

#[test]
fn local_capability_and_body() {
    assert!(local_capable(&CreateJob::text("x")).is_ok());
    assert!(local_capable(&CreateJob::commands(vec![])).is_ok());
    assert!(local_capable(&CreateJob::template("t", Value::Null)).is_ok());
    assert!(local_capable(&CreateJob::bytes(vec![0x1b, 0x40])).is_ok());
    assert!(local_capable(&CreateJob::bytes(b"%PDF-1.4".to_vec())).is_err());
    assert!(local_capable(&CreateJob::bytes(vec![0x89, b'P', b'N', b'G'])).is_err());
    assert!(local_capable(&CreateJob::bytes(vec![0x1b]).file_name("a.docx")).is_err());
    assert!(local_capable(&CreateJob::bytes(b"plain".to_vec())).is_err());
    assert!(local_capable(&CreateJob::text("x").sealed(true)).is_err());
    assert!(local_capable(&CreateJob::text("x").scheduled_for(Utc::now())).is_err());
    assert!(local_capable(&CreateJob::text("x").kind("pdf")).is_err());
    let b = local_body(&CreateJob::bytes(vec![0x1b, 0x40]).idempotency_key("k")).unwrap();
    assert_eq!(b["kind"], "escpos");
    assert_eq!(b["content"], "G0A=");
}

#[test]
fn token_claims_and_live() {
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"org":"org1","live":true,"jti":"j"}"#);
    let tok = format!("czl1.{payload}.c2ln");
    assert_eq!(token_claims(&tok).org, "org1");
    assert!(token_live(&tok));
    assert!(token_live("czd_x"));
    assert!(!token_live("czl1.bad.x"));
}

#[test]
fn config_validation() {
    let bad = [
        LocalConfig::new(LocalMode::Local),
        LocalConfig::new(LocalMode::LocalFirst).station_url("http://192.168.1.20:7443"),
        LocalConfig::new(LocalMode::Local).station_url("https://192.168.1.20:7443/x"),
        LocalConfig::new(LocalMode::Local)
            .station_url("https://192.168.1.20:7443")
            .fingerprint("192.168.1.20", "abc"),
        LocalConfig::new(LocalMode::Local)
            .discover(true)
            .token("cz_live_x"),
        LocalConfig::new(LocalMode::Local)
            .discover(true)
            .all_locations(true)
            .wait(Duration::from_secs(60)),
        LocalConfig::new(LocalMode::Local)
            .discover(true)
            .all_locations(true)
            .token_ttl_days(31),
        // Minting without a location (or all_locations) is refused.
        LocalConfig::new(LocalMode::LocalFirst).discover(true),
    ];
    for (i, cfg) in bad.into_iter().enumerate() {
        let r = Client::builder()
            .api_key("cz_test_abcdefghijklmnopqrstuvwxyz")
            .local(cfg)
            .build();
        assert!(matches!(r, Err(Error::Config(_))), "{i}: accepted");
    }
    let c = client(
        LocalConfig::new(LocalMode::LocalFirst)
            .discover(true)
            .location_id("loc1"),
    );
    assert_eq!(c.local().mode(), LocalMode::LocalFirst);
    assert_eq!(
        "cloud_first".parse::<LocalMode>().unwrap(),
        LocalMode::CloudFirst
    );
    assert!("offline".parse::<LocalMode>().is_err());
    // The store key never contains the API key.
    assert!(!c.local().__store_key().contains("abcdefghij"));
}
