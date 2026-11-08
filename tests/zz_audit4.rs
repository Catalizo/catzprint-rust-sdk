//! The audit round 4 proof (scratchpad/audit4/sdk/rust/tests/zz_audit4.rs),
//! turned into a regression test: it used to seal to a small-order key and
//! print the stored token in `Debug` output.

#[cfg(feature = "sealed")]
#[test]
fn audit4_low_order_key_is_refused() {
    let mut pk = [0u8; 32];
    pk[0] = 1; // small-order point
    let r = catzprint::seal(&pk, b"secret receipt");
    assert!(
        matches!(r, Err(catzprint::Error::Sealing(_))),
        "sealed to a small-order key: {r:?}"
    );
}

#[cfg(feature = "local")]
#[test]
fn audit4_stored_token_debug_is_redacted() {
    let st = catzprint::StoredToken {
        token: "czl1.SECRET.SIG".into(),
        ..Default::default()
    };
    let out = format!("{st:?}");
    assert!(!out.contains("SECRET"), "{out}");
}
