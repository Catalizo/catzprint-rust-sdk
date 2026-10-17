//! Client-side sealing: NaCl sealed boxes (X25519 + XSalsa20-Poly1305),
//! compatible with libsodium's `crypto_box_seal`.

use base64::Engine as _;

use crate::error::{Error, Result};

/// Decodes a base64 X25519 public key (as served by `GET /v1/public/server-key`).
pub(crate) fn decode_public_key(b64: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| Error::Sealing("the server key isn't valid base64".into()))?;
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| Error::Sealing("the server key must be 32 bytes".into()))?;
    if key == [0u8; 32] {
        return Err(Error::Sealing("the server key is all zeros".into()));
    }
    Ok(key)
}

/// Seals `message` to a 32-byte X25519 public key.
///
/// The output is `ephemeral_pk (32) || box (len + 16)`, exactly what
/// libsodium's `crypto_box_seal` produces, so anyone with the matching
/// private key can open it with `crypto_box_seal_open` (or PyNaCl's
/// `SealedBox`).
#[cfg(feature = "sealed")]
pub fn seal(public_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>> {
    let pk = crypto_box::PublicKey::from(*public_key);
    pk.seal(&mut crypto_box::aead::OsRng, message)
        .map_err(|_| Error::Sealing("encryption failed".into()))
}

/// Seals `message` to a base64 public key. See [`seal`].
#[cfg(feature = "sealed")]
pub fn seal_base64_key(public_key_b64: &str, message: &[u8]) -> Result<Vec<u8>> {
    seal(&decode_public_key(public_key_b64)?, message)
}

/// Without the `sealed` feature, sealing is unavailable.
#[cfg(not(feature = "sealed"))]
pub(crate) fn seal(_public_key: &[u8; 32], _message: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Sealing(
        "sealed printing needs the `sealed` feature of the catzprint crate".into(),
    ))
}

#[cfg(all(test, feature = "sealed"))]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let sk = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        let pk = *sk.public_key().as_bytes();
        let sealed = seal(&pk, b"hello").unwrap();
        assert_eq!(sealed.len(), 32 + 5 + 16);
        assert_eq!(sk.unseal(&sealed).unwrap(), b"hello");
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(decode_public_key("!!").is_err());
        assert!(decode_public_key("AAAA").is_err());
    }
}
