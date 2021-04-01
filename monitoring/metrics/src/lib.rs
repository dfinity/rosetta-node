pub mod buckets;
mod registry;
pub use registry::MetricsRegistry;

use hyper::{server::conn::Http, service::service_fn, Body, Response};
use ic_config::metrics::{Config, Exporter};
use ic_crypto_tls_interfaces::{AllowedClients, SomeOrAllNodes, TlsHandshake};
use ic_interfaces::registry::RegistryClient;
use prometheus::{Encoder, TextEncoder};
use slog::{error, trace, warn};
use std::net::SocketAddr;
use std::string::String;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const LOG_INTERVAL_SECS: u64 = 30;

/// The type of a metrics runtime implementation.
pub struct MetricsRuntimeImpl {
    exporter: Exporter,
    metrics_registry: MetricsRegistry,
    crypto_tls: Option<(Arc<dyn RegistryClient>, Arc<dyn TlsHandshake + Send + Sync>)>,
    log: slog::Logger,
}

/// An implementation of the metrics runtime type.
impl MetricsRuntimeImpl {
    pub fn new(
        config: Config,
        metrics_registry: MetricsRegistry,
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<dyn TlsHandshake + Send + Sync>,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(slog::o!("Application" => "MetricsRuntime"));

        let metrics = Self {
            exporter: config.exporter,
            metrics_registry,
            crypto_tls: Some((registry_client, crypto)),
            log,
        };

        match metrics.exporter {
            Exporter::Http(socket_addr) => metrics.start_http(socket_addr),
            Exporter::Log => metrics.start_log(),
            Exporter::File(_) => {}
        };

        metrics
    }

    /// Create a MetricsRuntimeImpl supporting only HTTP for insecure use cases
    /// e.g. testing binaries where the node certificate may not be available.
    pub fn new_insecure(
        config: Config,
        metrics_registry: MetricsRegistry,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(slog::o!("Application" => "MetricsRuntime"));

        let metrics = Self {
            exporter: config.exporter,
            metrics_registry,
            crypto_tls: None,
            log,
        };

        match metrics.exporter {
            Exporter::Http(socket_addr) => metrics.start_http(socket_addr),
            Exporter::Log => metrics.start_log(),
            Exporter::File(_) => {}
        };

        metrics
    }

    /// Spawn a background task which dump the metrics to the log.  This task
    /// does not terminate and if/when we support clean shutdown this task will
    /// need to be joined.
    fn start_log(&self) {
        let log = self.log.clone();
        let metrics_registry = self.metrics_registry.clone();
        tokio::spawn(async move {
            let encoder = TextEncoder::new();
            let mut interval = tokio::time::interval(Duration::from_secs(LOG_INTERVAL_SECS));
            loop {
                interval.tick().await;

                let mut buffer = vec![];
                let metric_families = metrics_registry.prometheus_registry().gather();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                let metrics = String::from_utf8(buffer).unwrap();
                trace!(log, "{}", metrics);
            }
        });
    }

    /// Spawn a background task to accept and handle metrics connections.  This
    /// task does not terminate and if/when we support clean shutdown this
    /// task will need to be joined.
    fn start_http(&self, address: SocketAddr) {
        let metrics_registry = self.metrics_registry.clone();
        let log = self.log.clone();

        let aservice = service_fn(move |_req| {
            // Clone again to ensure that `metrics_registry` outlives this closure.
            let metrics_registry = metrics_registry.clone();
            let encoder = TextEncoder::new();

            async move {
                let metric_families = metrics_registry.prometheus_registry().gather();
                let mut buffer = vec![];
                encoder.encode(&metric_families, &mut buffer).unwrap();
                Ok::<_, hyper::Error>(Response::new(Body::from(buffer)))
            }
        });

        let crypto_tls = self.crypto_tls.clone();
        tokio::spawn(async move {
            let mut listener = match TcpListener::bind(&address).await {
                Err(e) => {
                    error!(log, "HTTP exporter server error: {}", e);
                    return;
                }
                Ok(listener) => listener,
            };
            let http = Http::new();
            loop {
                let log = log.clone();
                let http = http.clone();
                let aservice = aservice.clone();
                let crypto_tls = crypto_tls.clone();
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut b = [0 as u8; 1];
                        if stream.peek(&mut b).await.is_ok() {
                            if b[0] == 22 {
                                if let Some((registry_client, crypto)) = crypto_tls {
                                    // TLS
                                    let allowed_clients =
                                        AllowedClients::new(SomeOrAllNodes::All, Vec::new())
                                            .expect("invalid allowed clients");
                                    // Note: the unwrap() can't fail since we tested Some(crypto)
                                    // above.
                                    let registry_version = registry_client.get_latest_version();
                                    match crypto
                                        .perform_tls_server_handshake_temp_with_optional_client_auth(
                                            stream,
                                            allowed_clients,
                                            registry_version,
                                            )
                                        .await
                                        {
                                            Err(e) => warn!(log, "TLS error: {}", e),
                                            Ok((stream, _peer_id)) => {
                                                if let Err(e) =
                                                    http.serve_connection(stream, aservice).await
                                                    {
                                                        trace!(log, "Connection error: {}", e);
                                                    }
                                            }
                                        };
                                } else {
                                    trace!(log, "Connection error: unsupported HTTPS connection");
                                }
                            } else {
                                // HTTP
                                if let Err(e) = http.serve_connection(stream, aservice).await {
                                    trace!(log, "Connection error: {}", e);
                                }
                            }
                        }
                    });
                }
            }
        });
    }
}

impl Drop for MetricsRuntimeImpl {
    fn drop(&mut self) {
        if let Exporter::File(ref path) = self.exporter {
            match std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(path)
            {
                Ok(mut file) => {
                    let encoder = TextEncoder::new();
                    let metric_families = self.metrics_registry.prometheus_registry().gather();
                    encoder
                        .encode(&metric_families, &mut file)
                        .unwrap_or_else(|err| {
                            error!(
                                self.log,
                                "Failed to encode metrics to file {}: {}",
                                path.display(),
                                err
                            );
                        });
                }
                Err(err) => {
                    error!(self.log, "Failed to open file {}: {}", path.display(), err);
                }
            }
        }
    }
}

/// A timer to be used with `HistogramVec`, when the labels are not known ahead
/// of time (e.g. when observing request durations by response status).
pub struct Timer {
    /// Starting instant for the timer.
    start: Instant,
}

impl Timer {
    /// Starts a new timer.
    pub fn start() -> Self {
        Timer {
            start: Instant::now(),
        }
    }

    /// Returns the time elapsed since the timer was started (in seconds).
    pub fn elapsed(&self) -> f64 {
        let d = self.start.elapsed();
        let nanos = f64::from(d.subsec_nanos()) / 1e9;
        d.as_secs() as f64 + nanos
    }
}