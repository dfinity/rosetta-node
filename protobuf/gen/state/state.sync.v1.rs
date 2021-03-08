#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileInfo {
    #[prost(string, tag="1")]
    pub relative_path: std::string::String,
    #[prost(uint64, tag="2")]
    pub size_bytes: u64,
    #[prost(bytes, tag="3")]
    pub hash: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChunkInfo {
    #[prost(uint32, tag="1")]
    pub file_index: u32,
    #[prost(uint32, tag="2")]
    pub size_bytes: u32,
    #[prost(uint64, tag="3")]
    pub offset: u64,
    #[prost(bytes, tag="4")]
    pub hash: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Manifest {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, repeated, tag="2")]
    pub file_table: ::std::vec::Vec<FileInfo>,
    #[prost(message, repeated, tag="3")]
    pub chunk_table: ::std::vec::Vec<ChunkInfo>,
}
