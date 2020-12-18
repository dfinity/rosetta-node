use serde::{Deserialize, Serialize};

/// This is effecitively a duplicate of `parity_wasm::elements::Error`.  We
/// duplicate because `parity_wasm::elements::Error` does not derive `Serialize`
/// and `Deserialize` and we need to derive these as this error gets embedded in
/// other types that derive `Serialize` and `Deserialize`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParityWasmError {
    UnexpectedEof,
    InvalidMagic,
    UnsupportedVersion(u32),
    InconsistentLength { expected: usize, actual: usize },
    UnknownValueType(i8),
    UnknownTableElementType(i8),
    NonUtf8String,
    UnknownOpcode(u8),
    InvalidVarInt { signed: bool, size_bits: u8 },
    InconsistentMetadata,
    InvalidSectionId(u8),
    SectionsOutOfOrder,
    DuplicatedSections(u8),
    InvalidMemoryReference(u8),
    InvalidTableReference(u8),
    InvalidLimitsFlags(u8),
    UnknownFunctionForm(u8),
    InconsistentCode,
    InvalidSegmentFlags(u32),
    TooManyLocals,
    DuplicatedNameSubsections(u8),
    UnknownNameSubsectionType(u8),
    Other,
}

impl std::fmt::Display for ParityWasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::InvalidMagic => write!(f, "invalid magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version {}", v),
            Self::InconsistentLength { expected, actual } => write!(
                f,
                "inconsistent length (expected {}, actual {})",
                expected, actual
            ),
            Self::UnknownValueType(t) => {
                write!(f, "invalid/unknown value type declaration {:#x}", t)
            }
            Self::UnknownTableElementType(t) => {
                write!(f, "invalid/unknown table element type declaration {:#x}", t)
            }
            Self::NonUtf8String => write!(f, "non-utf8 string"),
            Self::UnknownOpcode(c) => write!(f, "unknown opcode {:#x}", c),
            Self::InvalidVarInt { signed, size_bits } => write!(
                f,
                "invalid {}{}",
                if *signed { "varint" } else { "varuint" },
                size_bits
            ),
            Self::InconsistentMetadata => write!(f, "inconsistent metadata"),
            Self::InvalidSectionId(id) => write!(f, "invalid section with id {}", id),
            Self::SectionsOutOfOrder => write!(f, "sections are out of order"),
            Self::DuplicatedSections(s) => write!(f, "duplicated sections with id {}", s),
            Self::InvalidMemoryReference(r) => write!(f, "invalid memory reference {}", r),
            Self::InvalidTableReference(r) => write!(f, "invalid table reference {}", r),
            Self::InvalidLimitsFlags(flags) => {
                write!(f, "invalid value {} used for flags in limits type", flags)
            }
            Self::UnknownFunctionForm(form) => {
                write!(f, "unknown function form {:#x} (should be 0x60)", form)
            }
            Self::InconsistentCode => write!(
                f,
                "number of function body entries and signatures does not match"
            ),
            Self::InvalidSegmentFlags(flags) => write!(
                f,
                "invalid segment flags {}, only flags 0, 1, and 2 are accepted on segments",
                flags
            ),
            Self::TooManyLocals => write!(f, "sum of counts of locals is greater than 2^32"),
            Self::DuplicatedNameSubsections(i) => write!(f, "duplicated name subsections {}", i),
            Self::UnknownNameSubsectionType(t) => {
                write!(f, "unknown name subsection type {:#x}", t)
            }
            Self::Other => write!(f, "unknown"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Different errors that be returned by `validate_wasm_binary`
pub enum WasmValidationError {
    /// Failure in party_wasm when deserializing the wasm module.  
    ParityDeserializeError(ParityWasmError),
    /// wasmtime::Module::validate() failed
    WasmtimeValidation(String),
    /// Module contains an invalid function signature
    InvalidFunctionSignature(String),
    /// Module contains an invalid import section
    InvalidImportSection(String),
    /// Module contains an invalid export section
    InvalidExportSection(String),
    /// Module contains an invalid data section
    InvalidDataSection(String),
    /// Failure when trying to compile in Lucet
    LucetCompilerErr(String),
}

impl std::fmt::Display for WasmValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParityDeserializeError(err) => {
                write!(f, "Failed to deserialize wasm module with {}", err)
            }
            Self::WasmtimeValidation(err) => {
                write!(f, "Wasmtime failed to validate wasm module {}", err)
            }
            Self::InvalidFunctionSignature(err) => {
                write!(f, "Wasm module has an invalid function signature. {}", err)
            }
            Self::InvalidImportSection(err) => {
                write!(f, "Wasm module has an invalid import section. {}", err)
            }
            Self::InvalidExportSection(err) => {
                write!(f, "Wasm module has an invalid export section. {}", err)
            }
            Self::InvalidDataSection(err) => {
                write!(f, "Wasm module has an invalid data section. {}", err)
            }
            Self::LucetCompilerErr(err) => write!(
                f,
                "Validation failed due to \"{}\" compile error in Lucet",
                err
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Different errors that can be returned by `instrument`
pub enum WasmInstrumentationError {
    /// Failure in party_wasm when deserializing the wasm module
    ParityDeserializeError(ParityWasmError),
    /// Failure in party_wasm when serializing the wasm module
    ParitySerializeError(ParityWasmError),
    /// Incorrect number of memory sections
    IncorrectNumberMemorySections { expected: usize, got: usize },
}

impl std::fmt::Display for WasmInstrumentationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParityDeserializeError(err) => {
                write!(f, "Failed to deserialize wasm module with {}", err)
            }
            Self::ParitySerializeError(err) => {
                write!(f, "Failed to serialize wasm module with {}", err)
            }
            Self::IncorrectNumberMemorySections { expected, got } => write!(
                f,
                "Wasm module has {} memory sections but should have had {}",
                got, expected
            ),
        }
    }
}
