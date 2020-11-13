use candid::error::Result;
use candid::ser::IDLBuilder;
use candid::CandidType;

/// A tuple of values, length 0-7, all of which implement the CandidType trait.
///
/// This trait maps single values to multiple candid arguments.
///
/// This exists to help [`encode_args`](fn.encode_args.html) work without
/// macros.
pub trait EncodeArguments {
    fn encode_arguments(self, ser: &mut IDLBuilder) -> Result<&mut IDLBuilder>;
}

impl EncodeArguments for () {
    fn encode_arguments(self, ser: &mut IDLBuilder) -> Result<&mut IDLBuilder> {
        Ok(ser)
    }
}
impl<A1: CandidType> EncodeArguments for (A1,) {
    fn encode_arguments(self, ser: &mut IDLBuilder) -> Result<&mut IDLBuilder> {
        let (a1,) = self;
        ser.arg(&a1)
    }
}

impl<A1: CandidType, A2: CandidType> EncodeArguments for (A1, A2) {
    fn encode_arguments(self, ser: &mut IDLBuilder) -> Result<&mut IDLBuilder> {
        let (a1, a2) = self;
        let ser = (a1,).encode_arguments(ser)?;
        ser.arg(&a2)
    }
}

impl<A1: CandidType, A2: CandidType, A3: CandidType> EncodeArguments for (A1, A2, A3) {
    fn encode_arguments(self, ser: &mut IDLBuilder) -> Result<&mut IDLBuilder> {
        let (a1, a2, a3) = self;
        let ser = (a1, a2).encode_arguments(ser)?;
        ser.arg(&a3)
    }
}

impl<A1: CandidType, A2: CandidType, A3: CandidType, A4: CandidType> EncodeArguments
    for (A1, A2, A3, A4)
{
    fn encode_arguments(self, ser: &mut IDLBuilder) -> Result<&mut IDLBuilder> {
        let (a1, a2, a3, a4) = self;
        let ser = (a1, a2, a3).encode_arguments(ser)?;
        ser.arg(&a4)
    }
}

/// Serializes a tuple of rust values to a list of candid arguments.
///
/// This is the inverse of [`decode_args`](../de/fn.decode_args.html)
///
/// * `arguments` - A tuple of values all of which implement the
///   [`CandidType`](../types/trait.CandidType.html) trait
pub fn encode_args<Tuple: EncodeArguments>(arguments: Tuple) -> Result<Vec<u8>> {
    let mut ser = IDLBuilder::new();
    arguments.encode_arguments(&mut ser)?.serialize_to_vec()
}

/// Serializes a single rust value to a single candid argument.
pub fn encode_one<Candid: CandidType>(argument: Candid) -> Result<Vec<u8>> {
    encode_args((argument,))
}
