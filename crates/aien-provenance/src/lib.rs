use aien_protocol_types::Digest32;
use bitflags::bitflags;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub fn compute_sha256(bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Digest32::from_bytes(arr)
}

pub fn compute_canonical_json_digest<T: Serialize>(val: &T) -> Result<Digest32, serde_json::Error> {
    let json_bytes = serde_json::to_vec(val)?;
    Ok(compute_sha256(&json_bytes))
}

pub fn combine_digests(d1: &Digest32, d2: &Digest32) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(d1.as_bytes());
    hasher.update(d2.as_bytes());
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Digest32::from_bytes(arr)
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct GrantPermissions: u32 {
        const READ = 0b0000_0001;
        const EVALUATE = 0b0000_0010;
        const TRAIN = 0b0000_0100;
        const DISTILL = 0b0000_1000;
        const REDISTRIBUTE = 0b0001_0000;
        const COMMERCIAL = 0b0010_0000;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceGrant {
    pub grant_id: Uuid,
    pub source_uri: String,
    pub license_spdx: String,
    pub permissions: GrantPermissions,
    pub issuer: String,
    pub issuer_signature: Option<Vec<u8>>,
    pub expires_at_epoch_sec: Option<u64>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    #[error("Source grant permission denied: required {required:?}, granted {granted:?}")]
    PermissionDenied {
        required: GrantPermissions,
        granted: GrantPermissions,
    },
    #[error("Incompatible license: {license} not in allowed set")]
    IncompatibleLicense { license: String },
    #[error("Grant has expired at {0}")]
    GrantExpired(u64),
    #[error("Missing signature from authority")]
    MissingSignature,
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

impl SourceGrant {
    pub fn new(
        source_uri: String,
        license_spdx: String,
        permissions: GrantPermissions,
        issuer: String,
    ) -> Self {
        Self {
            grant_id: Uuid::new_v4(),
            source_uri,
            license_spdx,
            permissions,
            issuer,
            issuer_signature: None,
            expires_at_epoch_sec: None,
        }
    }

    pub fn with_expiration(mut self, expires_at_epoch_sec: u64) -> Self {
        self.expires_at_epoch_sec = Some(expires_at_epoch_sec);
        self
    }

    /// Computes the deterministic SHA-256 digest of the unsigned grant fields.
    pub fn compute_unsigned_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(self.grant_id.as_bytes());
        hasher.update(self.source_uri.as_bytes());
        hasher.update(self.license_spdx.as_bytes());
        hasher.update(self.permissions.bits().to_le_bytes());
        hasher.update(self.issuer.as_bytes());
        if let Some(exp) = self.expires_at_epoch_sec {
            hasher.update(b"exp:present");
            hasher.update(exp.to_le_bytes());
        } else {
            hasher.update(b"exp:none");
        }
        Digest32(hasher.finalize().into())
    }

    /// Signs the grant using the authority signing key.
    pub fn sign(&mut self, authority_signing_key: &SigningKey) {
        let digest = self.compute_unsigned_digest();
        let sig: Signature = authority_signing_key.sign(&digest.0);
        self.issuer_signature = Some(sig.to_bytes().to_vec());
    }

    /// Verifies the cryptographic signature of the grant against the authority verifying key.
    pub fn verify_signature(
        &self,
        authority_verifying_key: &VerifyingKey,
    ) -> Result<(), ProvenanceError> {
        let Some(ref sig_bytes) = self.issuer_signature else {
            return Err(ProvenanceError::MissingSignature);
        };
        let sig = Signature::from_slice(sig_bytes)
            .map_err(|e| ProvenanceError::InvalidSignatureFormat(e.to_string()))?;
        let digest = self.compute_unsigned_digest();
        authority_verifying_key
            .verify(&digest.0, &sig)
            .map_err(|e| ProvenanceError::SignatureVerificationFailed(e.to_string()))
    }

    /// Verifies that the grant has not expired given current epoch timestamp in seconds.
    pub fn verify_validity(&self, current_epoch_sec: u64) -> Result<(), ProvenanceError> {
        if let Some(exp) = self.expires_at_epoch_sec {
            if current_epoch_sec > exp {
                return Err(ProvenanceError::GrantExpired(exp));
            }
        }
        Ok(())
    }

    pub fn verify_permission(&self, required: GrantPermissions) -> Result<(), ProvenanceError> {
        if self.permissions.contains(required) {
            Ok(())
        } else {
            Err(ProvenanceError::PermissionDenied {
                required,
                granted: self.permissions,
            })
        }
    }

    pub fn verify_license(&self, allowed_licenses: &[&str]) -> Result<(), ProvenanceError> {
        if allowed_licenses
            .iter()
            .any(|&l| l.eq_ignore_ascii_case(&self.license_spdx))
        {
            Ok(())
        } else {
            Err(ProvenanceError::IncompatibleLicense {
                license: self.license_spdx.clone(),
            })
        }
    }

    /// Performs complete authorization verification: license, permissions, expiration, and authority signature.
    pub fn verify_all(
        &self,
        required_permissions: GrantPermissions,
        allowed_licenses: &[&str],
        current_epoch_sec: u64,
        authority_verifying_key: Option<&VerifyingKey>,
    ) -> Result<(), ProvenanceError> {
        self.verify_license(allowed_licenses)?;
        self.verify_permission(required_permissions)?;
        self.verify_validity(current_epoch_sec)?;
        if let Some(vk) = authority_verifying_key {
            self.verify_signature(vk)?;
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Digest32 {
        compute_canonical_json_digest(self).unwrap_or(Digest32::ZERO)
    }
}

/// Bytes in a SEC1 compressed P-256 public key (first byte 0x02 or 0x03).
pub const P256_KEY_LEN: usize = 33;
/// Bytes in a raw P-256 ECDSA signature, `r` then `s`.
pub const P256_SIG_LEN: usize = 64;

/// The SEC1 compressed encoding of the verifying key of `key`, the form the
/// fixed-width records of `specs/microjob` and `specs/discovery-capsule` carry.
pub fn p256_compressed_key(key: &SigningKey) -> [u8; P256_KEY_LEN] {
    let point = VerifyingKey::from(key).to_sec1_point(true);
    let mut out = [0u8; P256_KEY_LEN];
    out.copy_from_slice(point.as_bytes());
    out
}

/// ECDSA P-256 / SHA-256 signature over `message`, normalized to low S so one
/// message and key have one accepted signature form per nonce.
pub fn p256_sign_low_s(key: &SigningKey, message: &[u8]) -> [u8; P256_SIG_LEN] {
    let sig: Signature = key.sign(message);
    let mut out = [0u8; P256_SIG_LEN];
    out.copy_from_slice(&sig.normalize_s().to_bytes());
    out
}

/// Verify a raw low-S ECDSA P-256 / SHA-256 signature over `message` against
/// a SEC1 compressed public key. A high-S signature is refused even when it
/// is mathematically valid (malleability).
pub fn p256_verify_low_s(
    public_key: &[u8; P256_KEY_LEN],
    message: &[u8],
    signature: &[u8; P256_SIG_LEN],
) -> Result<(), ProvenanceError> {
    if public_key[0] != 0x02 && public_key[0] != 0x03 {
        return Err(ProvenanceError::InvalidSignatureFormat(
            "public key is not SEC1 compressed".into(),
        ));
    }
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| ProvenanceError::InvalidSignatureFormat(e.to_string()))?;
    let sig = Signature::from_slice(signature)
        .map_err(|e| ProvenanceError::InvalidSignatureFormat(e.to_string()))?;
    if sig.normalize_s() != sig {
        return Err(ProvenanceError::InvalidSignatureFormat(
            "high-S signature".into(),
        ));
    }
    vk.verify(message, &sig)
        .map_err(|e| ProvenanceError::SignatureVerificationFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_deterministic() {
        let d1 = compute_sha256(b"hello aien protocols");
        let d2 = compute_sha256(b"hello aien protocols");
        assert_eq!(d1, d2);
        assert_ne!(d1, Digest32::ZERO);
    }

    #[test]
    fn test_source_grant_permissions_and_licensing() {
        let grant = SourceGrant::new(
            "https://huggingface.co/datasets/aien/benchmark".to_string(),
            "Apache-2.0".to_string(),
            GrantPermissions::READ | GrantPermissions::EVALUATE | GrantPermissions::TRAIN,
            "Atlas Authority".to_string(),
        );

        assert!(grant.verify_permission(GrantPermissions::TRAIN).is_ok());
        assert!(grant.verify_permission(GrantPermissions::DISTILL).is_err());
        assert!(grant.verify_license(&["Apache-2.0", "MIT"]).is_ok());
        assert!(grant.verify_license(&["GPL-3.0"]).is_err());
    }

    #[test]
    fn test_source_grant_signature_and_expiration() {
        let signing_key = SigningKey::from_slice(&[33u8; 32]).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);

        let mut grant = SourceGrant::new(
            "https://hf.co/datasets/aien/verified".to_string(),
            "Apache-2.0".to_string(),
            GrantPermissions::TRAIN | GrantPermissions::DISTILL,
            "Atlas Provenance Authority".to_string(),
        )
        .with_expiration(1000);

        // Missing signature rejected
        assert_eq!(
            grant.verify_signature(&verifying_key),
            Err(ProvenanceError::MissingSignature)
        );

        // Sign grant
        grant.sign(&signing_key);
        assert!(grant.verify_signature(&verifying_key).is_ok());

        // Wrong verifying key rejected
        let other_key = VerifyingKey::from(&SigningKey::from_slice(&[44u8; 32]).unwrap());
        assert!(grant.verify_signature(&other_key).is_err());

        // Validity checks
        assert!(grant.verify_validity(999).is_ok());
        assert_eq!(
            grant.verify_validity(1001),
            Err(ProvenanceError::GrantExpired(1000))
        );

        // verify_all succeeds within window with valid key
        assert!(grant
            .verify_all(
                GrantPermissions::TRAIN,
                &["Apache-2.0"],
                950,
                Some(&verifying_key)
            )
            .is_ok());
    }

    #[test]
    fn test_p256_region_signature_low_s() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pubkey = p256_compressed_key(&key);
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
        let sig = p256_sign_low_s(&key, b"region");
        assert!(p256_verify_low_s(&pubkey, b"region", &sig).is_ok());
        assert!(p256_verify_low_s(&pubkey, b"regioN", &sig).is_err());

        // The high-S twin of a valid signature is refused.
        let parsed = Signature::from_slice(&sig).unwrap();
        let (r, s) = parsed.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();
        let mut high_bytes = [0u8; P256_SIG_LEN];
        high_bytes.copy_from_slice(&high.to_bytes());
        assert!(p256_verify_low_s(&pubkey, b"region", &high_bytes).is_err());
    }
}
