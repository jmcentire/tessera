use crate::error::TesseraError;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Trait for signing byte payloads.
pub trait Signer {
    /// Sign the given bytes and return the signature as hex.
    fn sign(&self, data: &[u8]) -> Result<String, TesseraError>;

    /// Return the public key as hex.
    fn public_key_hex(&self) -> String;
}

/// Trait for verifying signatures.
pub trait Verifier {
    /// Verify a hex-encoded signature against data and a hex-encoded public key.
    fn verify(pubkey_hex: &str, data: &[u8], sig_hex: &str) -> Result<(), TesseraError>;
}

/// Ed25519 signer backed by ed25519-dalek.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Create a new signer from raw secret key bytes (32 bytes).
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    /// Generate a new random signer.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Export the full keypair (secret + public) as hex (128 hex chars).
    pub fn keypair_hex(&self) -> String {
        let secret = self.signing_key.to_bytes();
        let public = self.verifying_key().to_bytes();
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&secret);
        combined.extend_from_slice(&public);
        hex::encode(combined)
    }

    /// Import a signer from a hex-encoded keypair (128 hex chars).
    pub fn from_keypair_hex(hex_str: &str) -> Result<Self, TesseraError> {
        let bytes =
            hex::decode(hex_str).map_err(|e| TesseraError::Crypto(format!("invalid hex: {e}")))?;
        if bytes.len() != 64 {
            return Err(TesseraError::Crypto(format!(
                "keypair must be 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes[..32]);
        Ok(Self::from_bytes(&secret))
    }

    /// Get the public key as hex.
    pub fn pubkey_hex(&self) -> String {
        self.public_key_hex()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Result<String, TesseraError> {
        use ed25519_dalek::Signer as DalekSigner;
        let sig = self.signing_key.sign(data);
        Ok(hex::encode(sig.to_bytes()))
    }

    fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().as_bytes())
    }
}

/// Ed25519 verifier.
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(pubkey_hex: &str, data: &[u8], sig_hex: &str) -> Result<(), TesseraError> {
        let pubkey_bytes = hex::decode(pubkey_hex)
            .map_err(|e| TesseraError::Crypto(format!("invalid pubkey hex: {e}")))?;
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| TesseraError::Crypto(format!("invalid signature hex: {e}")))?;

        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| TesseraError::Crypto("pubkey must be 32 bytes".into()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| TesseraError::Crypto("signature must be 64 bytes".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|e| TesseraError::Crypto(format!("invalid pubkey: {e}")))?;
        let signature = Signature::from_bytes(&sig_arr);

        use ed25519_dalek::Verifier as DalekVerifier;
        verifying_key
            .verify(data, &signature)
            .map_err(|e| TesseraError::InvalidSignature(format!("{e}")))
    }
}

/// Compute SHA-256 hash of data, return hex-encoded string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute SHA-256 hash of canonical JSON state representation.
pub fn hash_state(state: &crate::types::State) -> Result<String, TesseraError> {
    let canonical = canonical_json(state)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

/// Produce canonical JSON: sorted keys, no whitespace, deterministic.
pub fn canonical_json<T: serde::Serialize>(value: &T) -> Result<String, TesseraError> {
    // serde_json with BTreeMap keys are already sorted.
    // We serialize without pretty-printing for canonical form.
    serde_json::to_string(value)
        .map_err(|e| TesseraError::Serialization(format!("canonical JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn sign_and_verify() {
        let signer = Ed25519Signer::generate();
        let data = b"hello tessera";

        let sig = signer.sign(data).unwrap();
        let pubkey = signer.public_key_hex();

        Ed25519Verifier::verify(&pubkey, data, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_data() {
        let signer = Ed25519Signer::generate();
        let sig = signer.sign(b"correct data").unwrap();
        let pubkey = signer.public_key_hex();

        let result = Ed25519Verifier::verify(&pubkey, b"wrong data", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();
        let data = b"some data";

        let sig = signer1.sign(data).unwrap();
        let wrong_pubkey = signer2.public_key_hex();

        let result = Ed25519Verifier::verify(&wrong_pubkey, data, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn sha256_deterministic() {
        let hash1 = sha256_hex(b"hello");
        let hash2 = sha256_hex(b"hello");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn canonical_json_sorted_keys() {
        let mut map = BTreeMap::new();
        map.insert("z".to_string(), crate::types::Value::U64(1));
        map.insert("a".to_string(), crate::types::Value::U64(2));

        let json = canonical_json(&map).unwrap();
        // BTreeMap ensures sorted keys
        assert!(json.find("\"a\"").unwrap() < json.find("\"z\"").unwrap());
    }

    #[test]
    fn hash_state_deterministic() {
        let mut state = BTreeMap::new();
        state.insert("count".to_string(), crate::types::Value::U64(42));

        let h1 = hash_state(&state).unwrap();
        let h2 = hash_state(&state).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn pubkey_hex_is_64_chars() {
        let signer = Ed25519Signer::generate();
        assert_eq!(signer.public_key_hex().len(), 64);
    }
}
