//! Data types for the Edwards-curve Digital Signature Algorithm

pub mod ed25519 {
    //! Data types for Ed25519
    use std::fmt;
    use std::hash::{Hash, Hasher};

    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    pub struct PublicKey(pub [u8; PublicKey::SIZE]);
    crate::derive_serde!(PublicKey, PublicKey::SIZE);

    impl PublicKey {
        pub const SIZE: usize = 32;
    }
    impl fmt::Debug for PublicKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "PublicKey(0x{})", hex::encode(&self.0[..]))
        }
    }

    #[derive(Copy, Clone)]
    pub struct Signature(pub [u8; Signature::SIZE]);
    crate::derive_serde!(Signature, Signature::SIZE);

    impl Signature {
        pub const SIZE: usize = 64;
    }
    impl fmt::Debug for Signature {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let hex_sig = hex::encode(&self.0[..]);
            write!(f, "Signature(0x{})", hex_sig)
        }
    }
    impl PartialEq for Signature {
        fn eq(&self, other: &Self) -> bool {
            self.0[..] == other.0[..]
        }
    }
    impl Eq for Signature {}
    impl Hash for Signature {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0[..].hash(state);
        }
    }
}
