//! The artifact manager implementation.
//! Artifact Manager component manages all the Artifact Pools (consensus_pool,
//! ingress_pool, state_sync_pool, dkg_pool, certification_pool).
//! It provides an interface to Gossip allowing it to interact with all the
//! pools without knowing artifact related details.
use crate::actors::{ClientActor, NewArtifact};
use actix::prelude::Addr;
use ic_interfaces::{
    artifact_manager::{
        AdvertMismatchError, ArtifactAcceptance, ArtifactClient, ArtifactManager, OnArtifactError,
    },
    artifact_pool::UnvalidatedArtifact,
    time_source::TimeSource,
};
use ic_types::{
    artifact,
    artifact::{Advert, ArtifactKind, ArtifactPriorityFn, ArtifactTag},
    chunkable::{Chunkable, ChunkableArtifact},
    p2p, NodeId,
};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

/// In order to let ArtifactManager manage ArtifactClient that can be
/// parameterized by different artifact types, it has to use trait object and
/// there has to be a translation between various artifact sub-types to the
/// top-level enum types. SomeArtifactClient achieves both goals by acting as a
/// middleman.
///
/// The trick of this translation is to erase the type parameter from all
/// interface functions. So member functions of this trait mostly resembles
/// those of ArtifactClient, but uses top-level artifact types. The translation
/// is mostly handled via `From/Into`, `TryFrom/Into`, `AsMut` and `AsRef`
/// traits that are automatically derived between artifact subtypes and the
/// top-level types.
trait SomeArtifactClient: Send + Sync {
    fn on_artifact(
        &self,
        time_source: &dyn TimeSource,
        msg: artifact::Artifact,
        advert: p2p::GossipAdvert,
        peer_id: NodeId,
    ) -> Result<(), OnArtifactError<artifact::Artifact>>;
    fn has_artifact(&self, msg_id: &artifact::ArtifactId) -> Result<bool, ()>;
    fn get_validated_by_identifier(
        &self,
        msg_id: &artifact::ArtifactId,
    ) -> Result<Option<Box<dyn ChunkableArtifact>>, ()>;
    fn get_filter(&self, filter: &mut artifact::ArtifactFilter);
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert>;
    fn get_remaining_quota(&self, tag: artifact::ArtifactTag, peer_id: NodeId) -> Option<usize>;
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> Option<ArtifactPriorityFn>;
    fn get_chunk_tracker(
        &self,
        id: &artifact::ArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>>;
}

struct SomeArtifactClientImpl<Artifact: ArtifactKind + 'static> {
    client: Arc<dyn ArtifactClient<Artifact>>,
    addr: Addr<ClientActor<Artifact>>,
}

// The `Arc` wrapper below is unfortunate because Rust does not accept the
// alternative:
//
//     impl<Artifact: ArtifactKind, Client: ArtifactClient<Artifact>>
//         SomeArtifactClient for Client
impl<Artifact: ArtifactKind> SomeArtifactClient for SomeArtifactClientImpl<Artifact>
where
    Artifact::SerializeAs: TryFrom<artifact::Artifact, Error = artifact::Artifact>,
    Artifact::Message: ChunkableArtifact + Send + 'static,
    Advert<Artifact>:
        Into<p2p::GossipAdvert> + TryFrom<p2p::GossipAdvert, Error = p2p::GossipAdvert> + Eq,
    for<'a> &'a Artifact::Id: TryFrom<&'a artifact::ArtifactId, Error = &'a artifact::ArtifactId>,
    artifact::ArtifactFilter: AsMut<Artifact::Filter> + AsRef<Artifact::Filter>,
    for<'a> &'a Artifact::Attribute:
        TryFrom<&'a artifact::ArtifactAttribute, Error = &'a artifact::ArtifactAttribute>,
    Artifact::Attribute: 'static,
    Artifact::Id: 'static,
{
    fn on_artifact(
        &self,
        time_source: &dyn TimeSource,
        artifact: artifact::Artifact,
        advert: p2p::GossipAdvert,
        peer_id: NodeId,
    ) -> Result<(), OnArtifactError<artifact::Artifact>> {
        match (artifact.try_into(), advert.try_into()) {
            (Ok(msg), Ok(advert)) => {
                let result = self
                    .client
                    .as_ref()
                    .check_artifact_acceptance(msg, &peer_id)?;
                match result {
                    ArtifactAcceptance::Processed => (),
                    ArtifactAcceptance::AcceptedForProcessing(message) => {
                        Artifact::check_advert(&message, &advert).map_err(|expected| {
                            AdvertMismatchError {
                                received: advert.into(),
                                expected: expected.into(),
                            }
                        })?;
                        // do_send ignores mailbox capacity, which is what we want here
                        self.addr.do_send(NewArtifact(UnvalidatedArtifact {
                            message,
                            peer_id,
                            timestamp: time_source.get_relative_time(),
                        }))
                    }
                };
                Ok(())
            }
            (Err(artifact), _) => Err(OnArtifactError::NotProcessed(Box::new(artifact))),
            (_, Err(advert)) => Err(OnArtifactError::MessageConversionfailed(advert)),
        }
    }

    fn has_artifact(&self, msg_id: &artifact::ArtifactId) -> Result<bool, ()> {
        match msg_id.try_into() {
            Ok(id) => Ok(self.client.as_ref().has_artifact(id)),
            Err(_) => Err(()),
        }
    }

    fn get_validated_by_identifier<'b>(
        &self,
        msg_id: &artifact::ArtifactId,
    ) -> Result<Option<Box<dyn ChunkableArtifact>>, ()> {
        match msg_id.try_into() {
            Ok(id) => Ok(self
                .client
                .as_ref()
                .get_validated_by_identifier(id)
                .map(|x| Box::new(x) as Box<dyn ChunkableArtifact>)),
            Err(_) => Err(()),
        }
    }

    fn get_filter(&self, filter: &mut artifact::ArtifactFilter) {
        *filter.as_mut() = self.client.as_ref().get_filter()
    }

    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert> {
        self.client
            .as_ref()
            .get_all_validated_by_filter(filter.as_ref())
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<_>>()
    }

    fn get_remaining_quota(&self, tag: artifact::ArtifactTag, peer_id: NodeId) -> Option<usize> {
        if tag == Artifact::TAG {
            Some(self.client.as_ref().get_remaining_quota(peer_id))
        } else {
            None
        }
    }

    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> Option<ArtifactPriorityFn> {
        if tag == Artifact::TAG {
            let func = self.client.as_ref().get_priority_function()?;
            Some(Box::new(
                move |id: &'_ artifact::ArtifactId, attribute: &'_ artifact::ArtifactAttribute| {
                    match (id.try_into(), attribute.try_into()) {
                        (Ok(idd), Ok(attr)) => func(idd, attr),
                        _ => panic!("Priority function called on wrong id or attribute!"),
                    }
                },
            ))
        } else {
            None
        }
    }

    fn get_chunk_tracker(
        &self,
        artifact_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>> {
        match artifact_id.try_into() {
            Ok(artifact_id) => Some(self.client.as_ref().get_chunk_tracker(artifact_id)),
            Err(_) => None,
        }
    }
}

/// The ArtifactManager maintains a list of ArtifactClients, and is generic in
/// the client type. It mostly just forwards function calls to each client
/// depending on the artifact type.
///
/// For each client, there is both an actor component, and an ArtifactClient
/// component. The steps to create a client is:
///
/// 1. Create both the actor and ArtifactClient components.
/// 2. Actor is run in an arbiter.
/// 3. The ArtifactClient and actor address are then added to an ArtifactManager
///    through an ArtifactManagerMaker.
///
/// After we finish adding all clients to the 'ArtifactManagerMaker', an
/// 'ArtifactManager' is created.
//
// WARN: DO NOT ADD LIFETIME TO THIS STRUCT!
// Please talk to Paul or Eftychis if you really have to.
// We will convince you that you shouldn't.
#[allow(clippy::type_complexity)]
pub struct ArtifactManagerImpl {
    time_source: Arc<dyn TimeSource>,
    clients: HashMap<ArtifactTag, Box<dyn SomeArtifactClient>>,
}

impl ArtifactManagerImpl {
    /// Return a new 'ArtifactManager'.
    pub fn new(time_source: Arc<dyn TimeSource>) -> Self {
        Self {
            time_source,
            clients: HashMap::new(),
        }
    }
}

impl ArtifactManager for ArtifactManagerImpl {
    /// When a new artifact is received by Gossip, it is forwarded to
    /// ArtifactManager via the on_artifact call, which then forwards them
    /// to be process by a corresponding ArtifactClient based on the
    /// artifact type. Return `OnArtifactError::NotProcessed` if no clients
    /// were able to process it or an `OnArtifactError::ArtifactPoolError`
    /// if any other error has occurred.
    ///
    /// See `ArtifactClient::on_artifact` for more details.
    fn on_artifact(
        &self,
        msg: artifact::Artifact,
        advert: p2p::GossipAdvert,
        peer_id: &NodeId,
    ) -> Result<(), OnArtifactError<artifact::Artifact>> {
        let tag: ArtifactTag = (&msg).into();
        if let Some(client) = self.clients.get(&tag) {
            return client.on_artifact(self.time_source.as_ref(), msg, advert, *peer_id);
        }
        Err(OnArtifactError::NotProcessed(Box::new(msg)))
    }

    /// Checks if any of the ArtifactClient already has the artifact in the pool
    /// by the given identifier.
    fn has_artifact(&self, message_id: &artifact::ArtifactId) -> bool {
        let tag: ArtifactTag = message_id.into();

        match self.clients.get(&tag) {
            Some(client) => client.has_artifact(message_id).unwrap_or(false),
            None => false,
        }
    }

    /// Return a validated artifact by its identifier, or `None` if not found.
    // TODO: Currently it is not easy to return a reference to
    // the caller as some of the pools have the artifacts in the persistent
    // memory. This needs to be revisited.
    fn get_validated_by_identifier(
        &self,
        message_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn ChunkableArtifact + '_>> {
        let tag: ArtifactTag = message_id.into();

        match self.clients.get(&tag) {
            Some(client) => client
                .get_validated_by_identifier(message_id)
                .unwrap_or(None),
            None => None,
        }
    }

    /// Gets the filter that needs to be sent with re-transmission request to
    /// other peers. This filter should be a collection of all filters returned
    /// by the ArtifactClients.
    ///
    /// See `ArtifactClient::get_filter` for more details.
    fn get_filter(&self) -> artifact::ArtifactFilter {
        let mut filter = Default::default();
        self.clients
            .values()
            .for_each(|client| client.get_filter(&mut filter));
        filter
    }

    /// Get adverts of all validated artifacts by the filter from all clients.
    ///
    /// See `ArtifactClient::get_all_validated_by_filter` for more details.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert> {
        let mut adverts: Box<dyn Iterator<Item = p2p::GossipAdvert>> =
            Box::new(std::iter::empty::<p2p::GossipAdvert>());
        for client in self.clients.values() {
            adverts =
                Box::new(adverts.chain(client.get_all_validated_by_filter(filter).into_iter()))
        }
        adverts.collect()
    }

    /// Gets the remaining quota the given peer is allowed to consume for a
    /// specific client that is identified by the given artifact tag.
    ///
    /// See `ArtifactClient::get_remaining_quota` for more details.
    fn get_remaining_quota(&self, tag: artifact::ArtifactTag, peer_id: NodeId) -> Option<usize> {
        self.clients
            .get(&tag)
            .and_then(|client| client.get_remaining_quota(tag, peer_id))
    }

    /// Return the priority function for a specific client that is identified by
    /// the given artifact tag.
    ///
    /// See `ArtifactClient::get_priority_function` for more details.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> Option<ArtifactPriorityFn> {
        self.clients
            .get(&tag)
            .and_then(|client| client.get_priority_function(tag))
    }

    /// Get Chunk tracker for an advert.
    ///
    /// See `ArtifactClient::get_chunk_tracker` for more details
    fn get_chunk_tracker(
        &self,
        artifact_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>> {
        let tag: ArtifactTag = artifact_id.into();

        self.clients
            .get(&tag)
            .and_then(|client| client.get_chunk_tracker(&artifact_id))
    }
}

/// The ArtifactManagerMaker is a helper to create an ArtifactManager after we
/// add each client. It is separated from the ArtifactManager interface because
/// we want all clients to be added only once, and ArtifactManager can not be
/// modified after creation.
#[allow(clippy::type_complexity)]
pub struct ArtifactManagerMaker {
    time_source: Arc<dyn TimeSource>,
    clients: HashMap<ArtifactTag, Box<dyn SomeArtifactClient>>,
}

impl ArtifactManagerMaker {
    /// Return a new 'ArtifactManagerMaker'.
    pub fn new(time_source: Arc<dyn TimeSource>) -> Self {
        Self {
            time_source,
            clients: HashMap::new(),
        }
    }
    /// Add a new ArtifactClient (that is already wrapped in Arc) to be managed.
    pub fn add_arc_client<Artifact: ArtifactKind + 'static>(
        &mut self,
        client: Arc<dyn ArtifactClient<Artifact>>,
        addr: Addr<ClientActor<Artifact>>,
    ) where
        Artifact::SerializeAs: TryFrom<artifact::Artifact, Error = artifact::Artifact>,
        Artifact::Message: ChunkableArtifact + Send,
        Advert<Artifact>:
            Into<p2p::GossipAdvert> + TryFrom<p2p::GossipAdvert, Error = p2p::GossipAdvert> + Eq,
        for<'b> &'b Artifact::Id:
            TryFrom<&'b artifact::ArtifactId, Error = &'b artifact::ArtifactId>,
        artifact::ArtifactFilter: AsMut<Artifact::Filter> + AsRef<Artifact::Filter>,
        for<'b> &'b Artifact::Attribute:
            TryFrom<&'b artifact::ArtifactAttribute, Error = &'b artifact::ArtifactAttribute>,
        Artifact::Attribute: 'static,
    {
        let tag = Artifact::TAG;
        self.clients
            .insert(tag, Box::new(SomeArtifactClientImpl { client, addr }));
    }

    /// Add a new ArtifactClient to be managed.
    pub fn add_client<Artifact: ArtifactKind + 'static, Client: 'static>(
        &mut self,
        client: Client,
        addr: Addr<ClientActor<Artifact>>,
    ) where
        Client: ArtifactClient<Artifact>,
        Artifact::SerializeAs: TryFrom<artifact::Artifact, Error = artifact::Artifact>,
        Artifact::Message: ChunkableArtifact + Send,
        Advert<Artifact>:
            Into<p2p::GossipAdvert> + TryFrom<p2p::GossipAdvert, Error = p2p::GossipAdvert> + Eq,
        for<'b> &'b Artifact::Id:
            TryFrom<&'b artifact::ArtifactId, Error = &'b artifact::ArtifactId>,
        artifact::ArtifactFilter: AsMut<Artifact::Filter> + AsRef<Artifact::Filter>,
        for<'b> &'b Artifact::Attribute:
            TryFrom<&'b artifact::ArtifactAttribute, Error = &'b artifact::ArtifactAttribute>,
        Artifact::Attribute: 'static,
    {
        let tag = Artifact::TAG;
        self.clients.insert(
            tag,
            Box::new(SomeArtifactClientImpl {
                client: Arc::new(client) as Arc<_>,
                addr,
            }),
        );
    }

    /// Finish by creating an ArtifactManager component that manages all
    /// clients.
    pub fn finish(self) -> Arc<dyn ArtifactManager> {
        Arc::new(ArtifactManagerImpl {
            time_source: self.time_source,
            clients: self.clients,
        })
    }
}
