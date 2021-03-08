/// Combined threshold signature.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ThresholdSignature {
    #[prost(bytes, tag="1")]
    pub signature: std::vec::Vec<u8>,
    #[prost(message, optional, tag="2")]
    pub signer: ::std::option::Option<super::super::super::types::v1::NiDkgId>,
}
/// State tree root hash.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CertificationContent {
    #[prost(bytes, tag="2")]
    pub hash: std::vec::Vec<u8>,
}
/// Certification of state tree root hash.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Certification {
    #[prost(uint64, tag="1")]
    pub height: u64,
    #[prost(message, optional, tag="2")]
    pub content: ::std::option::Option<CertificationContent>,
    #[prost(message, optional, tag="3")]
    pub signature: ::std::option::Option<ThresholdSignature>,
}
/// XNet stream slice with certification and matching Merkle proof.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CertifiedStreamSlice {
    /// Serialized part of the state tree containing the stream data.
    #[prost(bytes, tag="1")]
    pub payload: std::vec::Vec<u8>,
    /// Witness that can be used to recompute the root hash from the payload.
    #[prost(bytes, tag="2")]
    pub merkle_proof: std::vec::Vec<u8>,
    /// Certification of the root hash.
    #[prost(message, optional, tag="3")]
    pub certification: ::std::option::Option<Certification>,
}
/// Tree with ordered, labeled edges.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LabeledTree {
    #[prost(oneof="labeled_tree::NodeEnum", tags="1, 2")]
    pub node_enum: ::std::option::Option<labeled_tree::NodeEnum>,
}
pub mod labeled_tree {
    /// Inner node with zero or more ordered, labeled children.
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct SubTree {
        /// Defined as `repeated` instead of `map` in order to preserve ordering.
        #[prost(message, repeated, tag="1")]
        pub children: ::std::vec::Vec<Child>,
    }
    /// A `SubTree`'s labeled child.
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Child {
        #[prost(bytes, tag="1")]
        pub label: std::vec::Vec<u8>,
        #[prost(message, optional, tag="2")]
        pub node: ::std::option::Option<super::LabeledTree>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum NodeEnum {
        #[prost(bytes, tag="1")]
        Leaf(std::vec::Vec<u8>),
        #[prost(message, tag="2")]
        SubTree(SubTree),
    }
}
/// A tree containing both data and merkle proofs.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MixedHashTree {
    #[prost(oneof="mixed_hash_tree::TreeEnum", tags="1, 2, 3, 4, 5")]
    pub tree_enum: ::std::option::Option<mixed_hash_tree::TreeEnum>,
}
pub mod mixed_hash_tree {
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Fork {
        #[prost(message, optional, boxed, tag="1")]
        pub left_tree: ::std::option::Option<::std::boxed::Box<super::MixedHashTree>>,
        #[prost(message, optional, boxed, tag="2")]
        pub right_tree: ::std::option::Option<::std::boxed::Box<super::MixedHashTree>>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Labeled {
        #[prost(bytes, tag="1")]
        pub label: std::vec::Vec<u8>,
        #[prost(message, optional, boxed, tag="2")]
        pub subtree: ::std::option::Option<::std::boxed::Box<super::MixedHashTree>>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum TreeEnum {
        #[prost(message, tag="1")]
        Empty(()),
        #[prost(message, tag="2")]
        Fork(Box<Fork>),
        #[prost(message, tag="3")]
        Labeled(Box<Labeled>),
        #[prost(bytes, tag="4")]
        LeafData(std::vec::Vec<u8>),
        #[prost(bytes, tag="5")]
        PrunedDigest(std::vec::Vec<u8>),
    }
}
/// Merkle proof - a subset of a `HashTree`.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Witness {
    #[prost(oneof="witness::WitnessEnum", tags="1, 2, 3, 4")]
    pub witness_enum: ::std::option::Option<witness::WitnessEnum>,
}
pub mod witness {
    /// Binary fork.
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Fork {
        #[prost(message, optional, boxed, tag="1")]
        pub left_tree: ::std::option::Option<::std::boxed::Box<super::Witness>>,
        #[prost(message, optional, boxed, tag="2")]
        pub right_tree: ::std::option::Option<::std::boxed::Box<super::Witness>>,
    }
    /// Labeled leaf or subtree.
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Node {
        #[prost(bytes, tag="3")]
        pub label: std::vec::Vec<u8>,
        #[prost(message, optional, boxed, tag="4")]
        pub sub_witness: ::std::option::Option<::std::boxed::Box<super::Witness>>,
    }
    /// Pruned leaf or subtree.
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Pruned {
        #[prost(bytes, tag="5")]
        pub digest: std::vec::Vec<u8>,
    }
    /// Marker for provided data (leaf or subtree).
    #[derive(Clone, PartialEq, ::prost::Message)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Known {
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum WitnessEnum {
        #[prost(message, tag="1")]
        Fork(Box<Fork>),
        #[prost(message, tag="2")]
        Node(Box<Node>),
        #[prost(message, tag="3")]
        Pruned(Pruned),
        #[prost(message, tag="4")]
        Known(Known),
    }
}
