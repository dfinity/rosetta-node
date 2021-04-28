#[macro_export]
macro_rules! use_gossip_malicious_behavior_on_chunk_request {
    ($trait_self:ident, $malicious_code: expr, $replica_code_code:block) => {
        if $trait_self.malicious_flags.maliciously_gossip_drop_requests
            || $trait_self
                .malicious_flags
                .maliciously_gossip_artifact_not_found
            || $trait_self
                .malicious_flags
                .maliciously_gossip_send_invalid_artifacts
            || $trait_self
                .malicious_flags
                .maliciously_gossip_send_many_artifacts
        {
            $malicious_code
        } else {
            $replica_code_code
        }
    };
}
