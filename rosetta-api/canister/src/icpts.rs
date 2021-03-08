use candid::CandidType;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Serialize, Deserialize, CandidType, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct ICPTs {
    /// Number of 10^-8 ICPs.
    /// Named because the equivalent part of a Bitcoin is called a Satoshi
    doms: u64,
}

pub const DECIMAL_PLACES: u32 = 8;
/// How many times can ICPs be divided
pub const ICP_SUBDIVIDABLE_BY: u64 = 100_000_000;

pub const TRANSACTION_FEE: ICPTs = ICPTs { doms: 137 };
pub const MIN_BURN_AMOUNT: ICPTs = TRANSACTION_FEE;

impl ICPTs {
    /// The maximum value of this construct is 2^64-1 Doms or Roughly 184
    /// Billion ICPTs
    pub const MAX: Self = ICPTs { doms: u64::MAX };

    /// Construct a new instance of ICPTs.
    /// This function will not allow you use more than 1 ICPTs worth of Doms.
    pub fn new(icpt: u64, doms: u64) -> Result<Self, String> {
        static CONSTRUCTION_FAILED: &str =
            "Constructing ICP failed because the underlying u64 overflowed";

        let icp_part = icpt
            .checked_mul(ICP_SUBDIVIDABLE_BY)
            .ok_or_else(|| CONSTRUCTION_FAILED.to_string())?;
        if doms >= ICP_SUBDIVIDABLE_BY {
            return Err(format!(
                "You've added too many Doms, make sure there are less than {}",
                ICP_SUBDIVIDABLE_BY
            ));
        }
        let doms = icp_part
            .checked_add(doms)
            .ok_or_else(|| CONSTRUCTION_FAILED.to_string())?;
        Ok(Self { doms })
    }

    pub const ZERO: Self = ICPTs { doms: 0 };

    /// ```
    /// # use ledger_canister::ICPTs;
    /// let icpt = ICPTs::from_icpts(12).unwrap();
    /// assert_eq!(icpt.unpack(), (12, 0))
    /// ```
    pub fn from_icpts(icp: u64) -> Result<Self, String> {
        Self::new(icp, 0)
    }

    /// Construct ICPTs from Doms, 10E8 Doms == 1 ICP
    /// ```
    /// # use ledger_canister::ICPTs;
    /// let icpt = ICPTs::from_doms(1200000200);
    /// assert_eq!(icpt.unpack(), (12, 200))
    /// ```
    pub fn from_doms(doms: u64) -> Self {
        ICPTs { doms }
    }

    /// Gets the total number of whole ICPTs
    /// ```
    /// # use ledger_canister::ICPTs;
    /// let icpt = ICPTs::new(12, 200).unwrap();
    /// assert_eq!(icpt.get_icpts(), 12)
    /// ```
    pub fn get_icpts(self) -> u64 {
        self.doms / ICP_SUBDIVIDABLE_BY
    }

    /// Gets the total number of Doms
    /// ```
    /// # use ledger_canister::ICPTs;
    /// let icpt = ICPTs::new(12, 200).unwrap();
    /// assert_eq!(icpt.get_doms(), 1200000200)
    /// ```
    pub fn get_doms(self) -> u64 {
        self.doms
    }

    /// Gets the total number of Doms not part of a whole ICPT
    /// The returned amount is always in the half-open interval [0, 1 ICP).
    /// ```
    /// # use ledger_canister::ICPTs;
    /// let icpt = ICPTs::new(12, 200).unwrap();
    /// assert_eq!(icpt.get_remainder_doms(), 200)
    /// ```
    pub fn get_remainder_doms(self) -> u64 {
        self.doms % ICP_SUBDIVIDABLE_BY
    }

    /// This returns the number of ICPTs and Doms
    /// ```
    /// # use ledger_canister::ICPTs;
    /// let icpt = ICPTs::new(12, 200).unwrap();
    /// assert_eq!(icpt.unpack(), (12, 200))
    /// ```
    pub fn unpack(self) -> (u64, u64) {
        (self.get_icpts(), self.get_remainder_doms())
    }
}

impl Add for ICPTs {
    type Output = Result<Self, String>;

    /// This returns a result, in normal operation this should always return Ok
    /// because of the cap in the total number of ICP, but when dealing with
    /// money it's better to be safe than sorry
    fn add(self, other: Self) -> Self::Output {
        let doms = self.doms.checked_add(other.doms).ok_or_else(|| {
            format!(
                "Add ICP {} + {} failed because the underlying u64 overflowed",
                self.doms, other.doms
            )
        })?;
        Ok(Self { doms })
    }
}

impl AddAssign for ICPTs {
    fn add_assign(&mut self, other: Self) {
        *self = (*self + other).expect("+= panicked");
    }
}

impl Sub for ICPTs {
    type Output = Result<Self, String>;

    fn sub(self, other: Self) -> Self::Output {
        let doms = self.doms.checked_sub(other.doms).ok_or_else(|| {
            format!(
                "Subtracting ICP {} - {} failed because the underlying u64 underflowed",
                self.doms, other.doms
            )
        })?;
        Ok(Self { doms })
    }
}

impl SubAssign for ICPTs {
    fn sub_assign(&mut self, other: Self) {
        *self = (*self - other).expect("-= panicked");
    }
}

/// ```
/// # use ledger_canister::ICPTs;
/// let icpt = ICPTs::new(12, 200).unwrap();
/// let s = format!("{}", icpt);
/// assert_eq!(&s[..], "12.00000200 ICP")
/// ```
impl fmt::Display for ICPTs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{:08} ICP",
            self.get_icpts(),
            self.get_remainder_doms()
        )
    }
}
