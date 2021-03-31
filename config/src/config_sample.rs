/// This constant contains a configuration of ic-replica with extra
/// comments describing the purpose and possible values of every
/// field.
///
/// This configuration is displayed as-is if the replica binary is
/// run with the `--sample-config` flag.
///
/// There are tests detecting significant deviations of this
/// configuration from the default configuration.  For example, the
/// test should break if:
///
/// * New sections/fields are added/removed.
/// * Types of leaf values are changed.
///
/// # Checking alternative values of options
///
/// For options having several fixed alternatives, there are tests
/// verifying that every alternative parses with the rest of the
/// config.
///
/// In order to take advantage of this feature, prefix alternatives
/// with a special "EXAMPLE:" marker in the comment above the
/// option.
///
/// For example, for a config of the following form
///
/// ```text
/// <prefix>
/// # EXAMPLE: y: "a"
/// # Some docs
/// #
/// # EXAMPLE: x: "b"
/// # More docs
/// #
/// # >>> NOTE: all the examples need to be defined in a single
/// #     continuous block of comments.
/// #
/// # >>> NOTE: there should be no blank line between the comment
/// #     and the value in the config.
/// y: "c"
/// <suffix>
/// ```
///
/// the tests will check that the following config files can be parsed
/// successfully:
///   * `<prefix> y: "a" <suffix>`
///   * `<prefix> x: "b" <suffix>`
///   * `<prefix> y: "c" <suffix>`
///
/// If the field is not set by default, leave an empty line after the
/// comment with alternatives:
///
/// ```text
/// # field x docs
/// # EXAMPLE: x: "a"
/// # EXAMPLE: x: "b"
/// # >>> The empty line below means that the field is not set by default.
///
/// # field y docs
/// # EXAMPLE: y: "bad"
/// y: "good"
/// ```

pub const SAMPLE_CONFIG: &str = r#"
{
    // ============================================
    // Global Replica Configuration
    // ============================================

    // Id of the subnet this node belongs to. This will be removed as soon as the replica can
    // retrieve its own subnet id from the registry.
    subnet_id: 0,

    // ============================================
    // Configuration of node transport
    // ============================================
    transport: {
        // IP address to bind if p2p_connections is not empty.
        node_ip: "127.0.0.1",

        // mapping of flow ids to TCP port number, also depth of send queue
        p2p_flows: [{flow_tag: 1, server_port: 3000, queue_size: 1024}],
    },
    // ============================================
    // Configuration of registry client
    // ============================================
    registry_client: {
        // Alternatives:
        //   * EXAMPLE: registry_canister_url: "https://registry.dfinity.org/",
        //     fetch updates from node at given url
        //     DEPRECATED (use local_store)
        //   * EXAMPLE: protobuf_file: "/tmp/registry.proto"
        //     read the registry from a file during boot
        //     DEPRECATED (use local_store)
        //   * EXAMPLE: bootstrap:{registry_canister_url: ["<url>"],initial_registry_file:"<path>"}
        //     used to bootstrap the NNS subnetwork. V1 is read from `initial_registry_file`,
        //     all request beyond V1 are forwarded to registry_canister_url
        //     DEPRECATED (use local_store)
        //   * EXAMPLE: local_store: "/tmp/local_store"
        //     read registry from the registry's local store.
        //
        // The default is not to specify it.
    },
    // ============================================
    // Configuration of the node state persistence.
    // ============================================
    state_manager: {
        // The directory that should be used to persist node state.
        state_root: "/tmp/ic_state"
    },
    // ============================================
    // Configuration of the node artifact pool persistence.
    // ============================================
    artifact_pool: {
        // The directory that should be used to persist consensus artifacts.
        consensus_pool_path: "/tmp/ic_consensus_pool",
        // The directory for the blockchain backup.
        backup_spool_path: "/tmp/ic_backup/"
    },
    // ============================================
    // Consensus related config.
    // ============================================
    consensus: {
        // Whether or not to detect starvation. Should only be set to false in tests.
        detect_starvation: true,
    },
    // ============================================
    // Configuration of the node state persistence.
    // ============================================
    crypto: {
        // The directory that should be used to persist node's cryptographic keys.
        crypto_root: "/tmp/ic_crypto"
    },
    // ========================================
    // Configuration of the message scheduling.
    // ========================================
    scheduler: {
        // The max number of cores to use for canister code execution.
        scheduler_cores: 1,

        // Maximum amount of instructions a single round can consume.
        max_instructions_per_round: 26843545600,

        // Maximum amount of instructions a single message's execution can consume.
        // This should be significantly smaller than `max_instructions_per_round`.
        max_instructions_per_message: 5368709120,
    },
    // ================================================
    // Configuration of the execution environment.
    // ================================================
    hypervisor: {
        // Which implementation of the runtime to use.
        // For now, "wasmtime" is the default option.
        embedder_type: "wasmtime",

        // Which technology to use to intercept Wasm memory changes.
        //
        // Alternatives:
        // - EXAMPLE: persistence_type: "sigsegv",
        //   Use memory persistence based on mprotect + SIGSEGV.
        // - EXAMPLE: persistence_type: "pagemap",
        //   Use memory persistence based on /proc/pid/pagemap (Linux) or Mac OS equivalent.
        persistence_type: "sigsegv",
    },
    // ====================================
    // Configuration of the HTTPS endpoint.
    // ====================================
    http_handler: {
        // The address to listen on.
        listen_addr: "127.0.0.1:8080"
    },
    // ==================================================
    // Configuration of the metrics collection subsystem.
    // ==================================================
    metrics: {
        // How to export metrics.
        //
        // Alternatives:
        // - EXAMPLE: exporter: "log",
        //   Periodically write prometheus metrics to the application log.
        // - EXAMPLE: exporter: { http: "127.0.0.1:9000" },
        //   Expose prometheus metrics on the specified address.
        // - EXAMPLE: exporter: { file: "/path/to/file" },
        //   Dump prometheus metrics to the specified file on shutdown.
        exporter: "log"
    },
    // ===================================
    // Configuration of the logging setup.
    // ===================================
    logger: {
        // The node id to append to log lines.
        node_id: 100,

        // The datacenter id to append to log lines.
        dc_id: 200,

        // The log level to use.
        // EXAMPLE: level: "critical",
        // EXAMPLE: level: "error",
        // EXAMPLE: level: "warning",
        // EXAMPLE: level: "info",
        // EXAMPLE: level: "debug",
        // EXAMPLE: level: "trace",
        level: "info",

        // The format of emitted log lines
        // EXAMPLE: format: "text_full",
        // EXAMPLE: format: "json",
        format: "text_full",

        // Output debug logs for these module paths
        // EXAMPLE: debug_overrides: ["ic_consensus::finalizer", "ic_messaging::coordinator"],
        debug_overrides: [],

        // Output logs for these tags
        // EXAMPLE: enabled_tags: ["artifact_tracing"],
        enabled_tags: [],

        // If `true` the async channel for low-priority messages will block instead of drop messages.
        // This behavior is required for instrumentation in System Testing until we have a
        // dedicated solution for instrumentation.
        //
        // The default for this value is `false` and thus matches the previously expected behavior in
        // production use cases.
        block_on_overflow: false,
    },
    // =================================
    // Configuration of Message Routing.
    // =================================
    message_routing: {
        // Currently empty, but will contain timeouts, max slice sizes etc.
    },
    // =================================
    // Configuration of Malicious behavior.
    // =================================
    malicious_behaviour: {
       allow_malicious_behaviour: false,
       maliciously_seg_fault: false,

       malicious_flags: {
         maliciously_gossip_drop_requests: false,
         maliciously_gossip_artifact_not_found: false,
         maliciously_gossip_send_many_artifacts: false,
         maliciously_gossip_send_invalid_artifacts: false,
         maliciously_gossip_send_late_artifacts: false,
         maliciously_propose_equivocating_blocks: false,
         maliciously_propose_empty_blocks: false,
         maliciously_finalize_all: false,
         maliciously_notarize_all: false,
         maliciously_tweak_dkg: false,
         maliciously_certify_invalid_hash: false,
         maliciously_malfunctioning_xnet_endpoint: false,
         maliciously_disable_execution: false,
         maliciously_disable_http_handler_ingress_validation: false,
       },
    },

    firewall: {
        config_file: "/var/lib/dfinity-node/nftables-ruleset",
        ipv4_config: "table ip ip4-firewall {\n  chain incoming {\n    type filter hook input priority 0; policy accept;\n  }\n}\n",
        ipv6_config: "table ip6 ip6-firewall {\n  chain incoming {\n    type filter hook input priority 0; policy drop;\n\n    ct state established,related accept\n\n    ct state invalid drop\n\n    iifname lo accept\n\n    icmpv6 type != { 137, 139 } accept\n\n    ip6 saddr $DCs accept\n  }\n}\n",
        dcs_var_name: "DCs",
        data_centers: [
            { dcop_principal_id: [1], ipv6_prefixes: "2607:fb58:9000:8::/64,2607:fb58:9005::/48" }, // SF
            { dcop_principal_id: [2], ipv6_prefixes: "2a00:fb01:400::/56" }, // ZH
        ],
    },

    // =================================
    // Configuration of registration parameters.
    // =================================
    registration: {
      pkcs11_keycard_transport_pin: "358138",
    },
    // =================================
    // NNS Registry Replicator
    // =================================
    // TODO(VER-277): This is a parameter that should not be under the control of the operator.
    // Hence it is in the wrong place and should be removed again.
    nns_registry_replicator: {
      poll_delay_duration_ms: 5000
    },
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    // This test verifies that the sample config can be loaded into
    // the replica.
    fn sample_config_is_deserializable() {
        let _ =
            json5::from_str::<Config>(SAMPLE_CONFIG).expect("sample config cannot be deserialized");
    }

    #[test]
    fn check_all_alternatives_parse() {
        const EXAMPLE_MARKER: &str = "EXAMPLE:";

        let mut line_variants: Vec<Vec<&str>> = Vec::new();
        let mut last_group: Vec<&str> = Vec::new();

        for line in SAMPLE_CONFIG.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                if let Some(pos) = line.find(EXAMPLE_MARKER) {
                    last_group.push(&line[pos + EXAMPLE_MARKER.len()..].trim())
                }
            } else if !trimmed.is_empty() || !last_group.is_empty() {
                if trimmed.starts_with('}') && !last_group.is_empty() {
                    line_variants.push(std::mem::replace(&mut last_group, Vec::new()));
                }
                last_group.push(line);
                line_variants.push(std::mem::replace(&mut last_group, Vec::new()));
            }
        }
        if !last_group.is_empty() {
            line_variants.push(last_group);
        }

        for (i, group) in line_variants.iter().enumerate() {
            if group.len() > 1 {
                let prefix = line_variants[..i]
                    .iter()
                    .map(|g| g[g.len() - 1])
                    .collect::<Vec<_>>()
                    .join("\n");
                let suffix = line_variants[i + 1..]
                    .iter()
                    .map(|g| g[g.len() - 1])
                    .collect::<Vec<_>>()
                    .join("\n");

                for &alternative in group.iter() {
                    let full_config = [&prefix, alternative, &suffix].join("\n");
                    if let Err(err) = json5::from_str::<Config>(&full_config) {
                        panic!("Failed to parse config variant {}: {}", full_config, err);
                    }
                }
            }
        }
    }
}
