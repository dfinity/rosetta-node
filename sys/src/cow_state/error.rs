use std::fmt;

#[derive(Debug)]
pub enum CowError {
    /// Slotdb error
    SlotdbError(String),
}

impl fmt::Display for CowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotdbError(e) => write!(f, "SlotdbError {}", e,),
        }
    }
}
