use candid::de::IDLDeserialize;
use candid::Result;
use serde::de::Deserialize;

pub trait DecodeArguments<'a>: Sized {
    fn decode_arguments(_de: IDLDeserialize<'a>) -> Result<(IDLDeserialize<'a>, Self)>;
}

// // Is this a sensible impl?
impl<'a> DecodeArguments<'a> for () {
    fn decode_arguments(de: IDLDeserialize<'a>) -> Result<(IDLDeserialize<'a>, ())> {
        Ok((de, ()))
    }
}

// This is all pretty mechanical, perhaps we could use code gen?
impl<'a, A1: Deserialize<'a>> DecodeArguments<'a> for (A1,) {
    fn decode_arguments(mut de: IDLDeserialize<'a>) -> Result<(IDLDeserialize<'a>, (A1,))> {
        let a_new = de.get_value()?;
        Ok((de, (a_new,)))
    }
}

impl<'a, A1: Deserialize<'a>, A2: Deserialize<'a>> DecodeArguments<'a> for (A1, A2) {
    fn decode_arguments(de: IDLDeserialize<'a>) -> Result<(IDLDeserialize<'a>, (A1, A2))> {
        let (mut de, (a1,)) = DecodeArguments::decode_arguments(de)?;
        let a_new = de.get_value()?;
        Ok((de, (a1, a_new)))
    }
}

impl<'a, A1: Deserialize<'a>, A2: Deserialize<'a>, A3: Deserialize<'a>> DecodeArguments<'a>
    for (A1, A2, A3)
{
    fn decode_arguments(de: IDLDeserialize<'a>) -> Result<(IDLDeserialize<'a>, (A1, A2, A3))> {
        let (mut de, (a1, a2)) = DecodeArguments::decode_arguments(de)?;
        let a_new = de.get_value()?;
        Ok((de, (a1, a2, a_new)))
    }
}

impl<'a, A1: Deserialize<'a>, A2: Deserialize<'a>, A3: Deserialize<'a>, A4: Deserialize<'a>>
    DecodeArguments<'a> for (A1, A2, A3, A4)
{
    fn decode_arguments(de: IDLDeserialize<'a>) -> Result<(IDLDeserialize<'a>, (A1, A2, A3, A4))> {
        let (mut de, (a1, a2, a3)) = DecodeArguments::decode_arguments(de)?;
        let a_new = de.get_value()?;
        Ok((de, (a1, a2, a3, a_new)))
    }
}
