//! Proves the sealed boxes this SDK makes open with libsodium (via PyNaCl).
#![cfg(feature = "sealed")]

use std::process::Command;

use base64::Engine as _;

const PY: &str = r#"
import base64, sys
from nacl.public import PrivateKey, SealedBox
sk = PrivateKey(base64.b64decode(sys.argv[1]))
print(SealedBox(sk).decrypt(base64.b64decode(sys.argv[2])).decode())
"#;

fn pynacl_available() -> bool {
    Command::new("python3")
        .args(["-c", "import nacl"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn pynacl_opens_sdk_sealed_box() {
    if !pynacl_available() {
        eprintln!("skipping: python3 with pynacl isn't installed");
        return;
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    // A fixed X25519 private key; its public key is computed by crypto_box.
    let sk_bytes = [7u8; 32];
    let sk = crypto_box::SecretKey::from(sk_bytes);
    let pk_b64 = b64.encode(sk.public_key().as_bytes());
    let message = "Table 4 — 2× soup, 1× bread ☕";
    let sealed = catzprint::seal_base64_key(&pk_b64, message.as_bytes()).unwrap();
    assert_eq!(sealed.len(), 48 + message.len());

    let out = Command::new("python3")
        .args(["-I", "-c", PY, &b64.encode(sk_bytes), &b64.encode(&sealed)])
        .output()
        .expect("run python3");
    assert!(
        out.status.success(),
        "pynacl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim_end(), message);

    // Every seal uses a fresh ephemeral key.
    let again = catzprint::seal_base64_key(&pk_b64, message.as_bytes()).unwrap();
    assert_ne!(sealed, again);
}
