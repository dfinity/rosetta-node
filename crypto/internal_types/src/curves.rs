//! Elliptic curve data types.
//!
//! Note: These are used in threshold signatures, multisignatures and
//! distributed key generation.

pub mod test_vectors;

pub mod bls12_381 {
    //! Data types for the BLS12_381 elliptic curve.
    //!
    //! This is a pairing curve from which we use two groups, "G1" and "G2".

    use std::fmt;
    use std::hash::{Hash, Hasher};

    /// A field representative in serialised, library independent form.
    ///
    /// # Content
    /// - bytes [0..32]: A big endian number
    ///
    /// # Interoperability
    /// - MIRACL uses a big endian 48 byte representation, so the leading 16
    ///   bytes in the MIRACL representation should zero.  The remaining bytes
    ///   should be identical to this 32 byte representation.
    /// - The IETF draft does not specify a serialisation for this: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
    #[derive(Copy, Clone, PartialEq, Eq, Hash)]
    pub struct Fr(pub [u8; Fr::SIZE]);
    crate::derive_serde!(Fr, Fr::SIZE);
    impl Fr {
        pub const SIZE: usize = 32;

        #[inline]
        pub fn as_bytes(&self) -> &[u8; Fr::SIZE] {
            &self.0
        }
    }
    impl fmt::Debug for Fr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Fr({:?})", hex::encode(&self.0[..]))
        }
    }

    /// A point in the group "G1" in serialised, library independent form.
    ///
    /// # Content
    /// - bit (`byte[0]>>7`): compression flag: Should always be set to 1 as the
    ///   48 byte representation is compressed.
    /// - bit (`byte[0]>>6`): infinity: 1 if the point is at infinity, zero
    ///   otherwise.
    /// - bit (`byte[0]>>5`): sort flag: In the compressed form, where only x is
    ///   provided, this gives the sign of y.
    /// - all remaining bits and bytes: ( `byte[0]&0x1f` concat `byte[1..=47]` )
    ///   The x coordinate in big endian format.
    ///
    /// # Interoperability
    /// - This representation is consistent with IETF draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
    ///   which specifies the "compressed serialization formats for E1 and E2
    ///   defined by [ZCash]"
    /// - This representation is different from the MIRACL library format, which
    ///   stores the flag bits in a separate leading byte.
    #[derive(Copy, Clone)]
    pub struct G1(pub [u8; G1::SIZE]);
    crate::derive_serde!(G1, G1::SIZE);

    impl G1 {
        pub const SIZE: usize = 48;
        pub const COMPRESSED_FLAG: u8 = 1 << 7;
        pub const INFINITY_FLAG: u8 = 1 << 6;
        pub const SIGN_FLAG: u8 = 1 << 5;
        pub const NON_FLAG_BITS: u8 = 0x1f;
        pub const FLAG_BYTE_OFFSET: usize = 0;
        pub const X_BYTES_OFFSET: usize = 0;

        #[inline]
        pub fn as_bytes(&self) -> &[u8; G1::SIZE] {
            &self.0
        }
    }
    impl fmt::Debug for G1 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "G1(0x{})", hex::encode(&self.0[..]))
        }
    }
    impl PartialEq for G1 {
        fn eq(&self, other: &Self) -> bool {
            self.0[..] == other.0[..]
        }
    }
    impl Eq for G1 {}
    impl Hash for G1 {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0[..].hash(state);
        }
    }

    /// A point in the group "G2".
    ///
    /// # Content
    /// - bit (`byte[0]>>7`): compression flag: Should always be set to 1 as the
    ///   96 byte representation is compressed.
    /// - bit (`byte[0]>>6`): infinity: 1 if the point is at infinity, zero
    ///   otherwise.
    /// - bit (`byte[0]>>5`): sort flag: In the compressed form, where only x is
    ///   provided, this gives the sign of y.
    /// - first 48 bytes excluding flags (`byte[0]&0x1f` concat `byte[1..=47]`):
    ///   The part "c1" of the x coordinate in big endian format.
    /// - next 48 bytes (`byte[48..=95]`): The part "c0" of the x coordinate in
    ///   big endian format
    ///
    /// # Interoperability
    /// - This representation is consistent with IETF draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
    ///   which specifies the "compressed serialization formats for E1 and E2
    ///   defined by [ZCash]"
    /// - This representation is different from the MIRACL library format, which
    ///   stores the flag bits in a separate leading byte.
    /// - Ordering is by c1, or by c0 if the c1 are identical.
    /// - Miracl refers to `c0` and `c1` as `a` and `b`.
    #[derive(Copy, Clone)]
    pub struct G2(pub [u8; G2::SIZE]);
    crate::derive_serde!(G2, G2::SIZE);

    impl G2 {
        pub const SIZE: usize = 96;
        pub const COMPRESSED_FLAG: u8 = 1 << 7;
        pub const INFINITY_FLAG: u8 = 1 << 6;
        pub const SIGN_FLAG: u8 = 1 << 5;
        pub const NON_FLAG_BITS: u8 = 0x1f;
        pub const FLAG_BYTE_OFFSET: usize = 0;
        pub const X1_BYTES_OFFSET: usize = 0;
        pub const X0_BYTES_OFFSET: usize = 48;

        #[inline]
        pub fn as_bytes(&self) -> &[u8; G2::SIZE] {
            &self.0
        }
    }
    impl fmt::Debug for G2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let hex_sig = hex::encode(&self.0[..]);
            write!(f, "G2(0x{})", hex_sig)
        }
    }
    impl PartialEq for G2 {
        fn eq(&self, other: &Self) -> bool {
            self.0[..] == other.0[..]
        }
    }
    impl Eq for G2 {}
    impl Hash for G2 {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0[..].hash(state);
        }
    }
}
