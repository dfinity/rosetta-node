use serde::{Deserialize, Serialize};
use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

/// Struct to handle cycles on the IC. They are maintained as a
/// simple u64. We implement our own arithmetic functions on them so that we can
/// ensure that they never overflow or underflow.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cycles(u64);

impl Cycles {
    pub const fn new(input: u64) -> Self {
        Self(input)
    }

    pub fn get(&self) -> u64 {
        self.0
    }
}

impl From<u64> for Cycles {
    fn from(input: u64) -> Self {
        Self::new(input)
    }
}

impl Add for Cycles {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign for Cycles {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_add(rhs.0)
    }
}

impl Sub for Cycles {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl SubAssign for Cycles {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_sub(rhs.0)
    }
}

impl Mul for Cycles {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self(self.0.saturating_mul(rhs.0))
    }
}

impl MulAssign for Cycles {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_mul(rhs.0)
    }
}

impl fmt::Display for Cycles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_addition() {
        assert_eq!(Cycles::from(0) + Cycles::from(0), Cycles::from(0));
        assert_eq!(
            Cycles::from(0) + Cycles::from(std::u64::MAX),
            Cycles::from(std::u64::MAX)
        );
        assert_eq!(
            Cycles::from(std::u64::MAX) + Cycles::from(std::u64::MAX),
            Cycles::from(std::u64::MAX)
        );
        assert_eq!(
            Cycles::from(std::u64::MAX) + Cycles::from(10),
            Cycles::from(std::u64::MAX)
        );
    }

    #[test]
    fn test_multiplication() {
        assert_eq!(Cycles::from(0) * Cycles::from(0), Cycles::from(0));
        assert_eq!(
            Cycles::from(0) * Cycles::from(std::u64::MAX),
            Cycles::from(0)
        );
        assert_eq!(
            Cycles::from(std::u64::MAX) * Cycles::from(std::u64::MAX),
            Cycles::from(std::u64::MAX)
        );
        assert_eq!(
            Cycles::from(std::u64::MAX) * Cycles::from(10),
            Cycles::from(std::u64::MAX)
        );
    }

    #[test]
    fn test_subtraction() {
        assert_eq!(Cycles::from(0) - Cycles::from(0), Cycles::from(0));
        assert_eq!(
            Cycles::from(0) - Cycles::from(std::u64::MAX),
            Cycles::from(0)
        );
        assert_eq!(
            Cycles::from(std::u64::MAX) - Cycles::from(std::u64::MAX),
            Cycles::from(0)
        );
        assert_eq!(
            Cycles::from(std::u64::MAX) - Cycles::from(10),
            Cycles::from(std::u64::MAX - 10)
        );
        assert_eq!(Cycles::from(0) - Cycles::from(10), Cycles::from(0));
    }
}
