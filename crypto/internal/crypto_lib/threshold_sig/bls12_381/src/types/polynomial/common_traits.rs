//! Fr, provided indirectly by the pairing library, does not support zeroizing
//! with the Zeroize trait so we implement it here ourselves.

use super::*;
use std::mem::{size_of, transmute};

pub fn zeroize_fr(fr: &mut Fr) {
    #[cfg_attr(tarpaulin, skip)]
    unsafe {
        transmute::<Fr, [u8; size_of::<Fr>()]>(*fr).copy_from_slice(&[0u8; size_of::<Fr>()]);
    }
}

impl Zeroize for Polynomial {
    fn zeroize(&mut self) {
        #[cfg_attr(tarpaulin, skip)]
        for fr in self.coefficients.iter_mut() {
            zeroize_fr(fr);
        }
    }
}

impl Drop for Polynomial {
    fn drop(&mut self) {
        self.zeroize();
    }
}
