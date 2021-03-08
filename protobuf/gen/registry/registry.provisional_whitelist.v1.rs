#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProvisionalWhitelist {
    #[prost(enumeration="provisional_whitelist::ListType", tag="1")]
    pub list_type: i32,
    /// This must be empty if list_type is of variant ALL.
    #[prost(message, repeated, tag="2")]
    pub set: ::std::vec::Vec<super::super::super::types::v1::PrincipalId>,
}
pub mod provisional_whitelist {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum ListType {
        Unspecified = 0,
        All = 1,
        Set = 2,
    }
}
