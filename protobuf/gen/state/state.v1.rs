#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateMetadata {
    #[prost(message, optional, tag="1")]
    pub manifest: ::std::option::Option<super::sync::v1::Manifest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatesMetadata {
    #[prost(btree_map="uint64, message", tag="1")]
    pub by_height: ::std::collections::BTreeMap<u64, StateMetadata>,
}
