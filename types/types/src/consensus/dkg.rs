use super::*;
use crate::{
    crypto::threshold_sig::ni_dkg::{
        config::NiDkgConfig, NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTranscript,
    },
    ReplicaVersion,
};
use ic_protobuf::types::v1 as pb;
use std::collections::BTreeMap;

/// Contains a Node's contribution to a DKG dealing.
pub type Message = BasicSigned<DealingContent>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DealingContent {
    version: ReplicaVersion,
    pub dealing: NiDkgDealing,
    pub dkg_id: NiDkgId,
}

impl DealingContent {
    pub fn new(dealing: NiDkgDealing, dkg_id: NiDkgId) -> Self {
        DealingContent {
            version: ReplicaVersion::default(),
            dealing,
            dkg_id,
        }
    }
}

impl From<&Message> for pb::DkgMessage {
    fn from(message: &Message) -> Self {
        Self {
            replica_version: message.content.version.to_string(),
            dkg_id: Some(pb::NiDkgId::from(message.content.dkg_id)),
            dealing: bincode::serialize(&message.content.dealing).unwrap(),
            signature: message.signature.signature.clone().get().0,
            signer: Some(crate::node_id_into_protobuf(message.signature.signer)),
        }
    }
}

impl HasVersion for DealingContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

/// The DKG summary will be present as the DKG payload at every block,
/// corresponding to the start of a new DKG interval.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Summary {
    /// The registry version used to create this summary.
    pub registry_version: RegistryVersion,
    /// The crypto configs of the currently computed DKGs, indexed by DKG Ids.
    pub configs: BTreeMap<NiDkgId, NiDkgConfig>,
    /// Current transcripts indexed by their tags. The values are guaranteed
    /// to be present, if a DKG is being computed for a given tag.
    current_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
    /// Transcripts for the next DKG interval. The values are not guaranteed to
    /// be present for any given tag (e.g., when the DKG computation
    /// failed); in this case we fall back the current transcript
    /// corresponding to this tag.
    next_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
    /// The length of the current interval in rounds (following the start
    /// block).
    pub interval_length: Height,
    /// The length of the next interval in rounds (following the start block).
    pub next_interval_length: Height,
    /// The height of the block conatining that summary.
    pub height: Height,
}

impl Summary {
    pub fn new(
        configs: Vec<NiDkgConfig>,
        current_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
        next_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
        registry_version: RegistryVersion,
        interval_length: Height,
        next_interval_length: Height,
        height: Height,
    ) -> Self {
        Self {
            configs: configs
                .into_iter()
                .map(|config| (config.dkg_id(), config))
                .collect(),
            current_transcripts,
            next_transcripts,
            registry_version,
            interval_length,
            next_interval_length,
            height,
        }
    }

    /// Adds provided transcripts as current trasncripts to the summary. Should
    /// be used for testing only.
    pub fn with_current_transcripts(
        mut self,
        current_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
    ) -> Self {
        self.current_transcripts = current_transcripts;
        self
    }

    /// Returns the current transcript for the given tag. Note that currently we
    /// expect that a valid summary contains the current transcript for any
    /// DKG tag.
    pub fn current_transcript(&self, tag: &NiDkgTag) -> &NiDkgTranscript {
        self.current_transcripts
            .get(tag)
            .unwrap_or_else(|| panic!("No current transcript available for tag {:?}", tag))
    }

    /// Returns the next transcript for the given tag if available.
    pub fn next_transcript(&self, tag: &NiDkgTag) -> Option<&NiDkgTranscript> {
        self.next_transcripts.get(tag)
    }

    /// Returns `true` if the provided height is included in the DKG interval
    /// corresponding to the current summary. Note that the summary block is
    /// considered to be part of the interval. For example, if the start height
    /// is 10 and the interval length is 5, we consider all heights from 10
    /// to 15 as being included in the interval.
    pub fn current_interval_includes(&self, height: Height) -> bool {
        let start = self.height;
        let end = start + self.interval_length;
        start <= height && height <= end
    }

    /// Returns `true` if the provided height is included in the next DKG
    /// interval. For example, if the current interval starts at height 10, the
    /// length of the current interval is 5, and the length of the following
    /// interval is 3, we consider all heights from 16 to 19 as being
    /// included in the next interval.
    pub fn next_interval_includes(&self, height: Height) -> bool {
        let start = (self.height + self.interval_length).increment();
        let end = start + self.next_interval_length;
        start <= height && height <= end
    }
}

fn build_transcripts_vec(
    transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
) -> Vec<pb::TaggedNiDkgTranscript> {
    transcripts
        .iter()
        .map(|(tag, transcript)| pb::TaggedNiDkgTranscript {
            tag: pb::NiDkgTag::from(tag) as i32,
            transcript: Some(pb::NiDkgTranscript::from(transcript)),
        })
        .collect()
}

impl From<&Summary> for pb::Summary {
    fn from(summary: &Summary) -> Self {
        Self {
            registry_version: summary.registry_version.get(),
            configs: summary
                .configs
                .values()
                .map(pb::NiDkgConfig::from)
                .collect(),
            current_transcripts: build_transcripts_vec(&summary.current_transcripts),
            next_transcripts: build_transcripts_vec(&summary.next_transcripts),
            interval_length: summary.interval_length.get(),
            next_interval_length: summary.next_interval_length.get(),
            height: summary.height.get(),
        }
    }
}

fn build_transcripts_map(
    transcripts: &[pb::TaggedNiDkgTranscript],
) -> Result<BTreeMap<NiDkgTag, NiDkgTranscript>, String> {
    transcripts
        .iter()
        .map(|tagged_transcript| {
            tagged_transcript
                .transcript
                .as_ref()
                .ok_or_else(|| String::from(""))
                .and_then(|t| {
                    Ok((
                        NiDkgTag::try_from(tagged_transcript.tag).map_err(|_| "")?,
                        NiDkgTranscript::try_from(t)?,
                    ))
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
}

impl TryFrom<pb::Summary> for Summary {
    type Error = String;
    fn try_from(summary: pb::Summary) -> Result<Self, Self::Error> {
        Ok(Self {
            registry_version: RegistryVersion::from(summary.registry_version),
            configs: summary
                .configs
                .into_iter()
                .map(|config| NiDkgConfig::try_from(config).map(|c| (c.dkg_id, c)))
                .collect::<Result<BTreeMap<_, _>, _>>()?,
            current_transcripts: build_transcripts_map(&summary.current_transcripts)?,
            next_transcripts: build_transcripts_map(&summary.next_transcripts)?,
            interval_length: Height::from(summary.interval_length),
            next_interval_length: Height::from(summary.next_interval_length),
            height: Height::from(summary.height),
        })
    }
}

/// The DKG payload is either the DKG Summary, if this payload belongs to a
/// start block of a new DKG interval, or a tuple containing the start height
/// and the set of valid dealings corresponding to the current interval.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Payload {
    Summary(Summary),
    Dealings(Height, Vec<Message>),
}

impl Payload {
    /// Indicates if the given DKG payload is a summary block.
    pub fn is_summary(&self) -> bool {
        match self {
            Payload::Summary(_) => true,
            _ => false,
        }
    }

    /// Returns the DKG summary. Panics if called on a dealings payload.
    pub fn summary(&self) -> &Summary {
        match self {
            Payload::Summary(summary) => summary,
            _ => unreachable!("No DKG summary available on a block with dealings."),
        }
    }

    pub fn payload_type(&self) -> &'static str {
        match self {
            Payload::Summary(_) => "summary",
            Payload::Dealings(_, _) => "dealings",
        }
    }
}

impl NiDkgTag {
    /// Returns the threshold (minimal number of nodes) required to accomplish a
    /// certain crypto-operation.
    pub fn threshold_for_subnet_of_size(&self, subnet_size: usize) -> Threshold {
        let committee_size = get_committee_size(subnet_size);
        let f = crate::consensus::get_faults_tolerated(committee_size);
        match self {
            NiDkgTag::LowThreshold => f + 1,
            NiDkgTag::HighThreshold => committee_size - f,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_correctly_calculate_threshold_for_ni_dkg_tag_low_threshold() {
        let low_threshold_tag = NiDkgTag::LowThreshold;
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(0), 1);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(1), 1);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(2), 1);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(3), 1);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(4), 2);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(5), 2);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(6), 2);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(28), 10);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(64), 22);
    }
    #[test]
    fn should_correctly_calculate_threshold_for_ni_dkg_tag_high_threshold() {
        let high_threshold_tag = NiDkgTag::HighThreshold;
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(0), 1);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(1), 1);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(2), 1);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(3), 1);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(4), 3);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(5), 3);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(6), 3);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(28), 19);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(64), 43);
    }

    #[test]
    fn should_correctly_calculate_faults_tolerated_for_committee_of_size() {
        use crate::consensus::get_faults_tolerated;
        assert_eq!(get_faults_tolerated(0), 0);
        assert_eq!(get_faults_tolerated(1), 0);
        assert_eq!(get_faults_tolerated(2), 0);
        assert_eq!(get_faults_tolerated(3), 0);
        assert_eq!(get_faults_tolerated(4), 1);
        assert_eq!(get_faults_tolerated(5), 1);
        assert_eq!(get_faults_tolerated(6), 1);
        assert_eq!(get_faults_tolerated(7), 2);
        assert_eq!(get_faults_tolerated(28), 9);
        assert_eq!(get_faults_tolerated(64), 21);
    }
}

impl From<&Payload> for pb::DkgPayload {
    fn from(payload: &Payload) -> Self {
        Self {
            val: Some(match payload {
                Payload::Summary(summary) => {
                    pb::dkg_payload::Val::Summary(pb::Summary::from(summary))
                }
                Payload::Dealings(summary_height, messages) => {
                    pb::dkg_payload::Val::Dealings(pb::Dealings {
                        dealings: messages.iter().map(pb::DkgMessage::from).collect(),
                        summary_height: summary_height.get(),
                    })
                }
            }),
        }
    }
}

impl TryFrom<pb::DkgPayload> for Payload {
    type Error = String;
    fn try_from(summary: pb::DkgPayload) -> Result<Self, Self::Error> {
        match summary.val.ok_or("Val missing in DkgPayload")? {
            pb::dkg_payload::Val::Summary(summary) => {
                Ok(Payload::Summary(Summary::try_from(summary)?))
            }
            // TODO: Support dealings, although the protobufs are intended
            // mostly for use with cups so this may not be necessary since cups
            // will always have Summary values.
            _ => Err(String::from("Deserialization of dkg payloads that are not summary blocks is not currently supported"))
        }
    }
}
